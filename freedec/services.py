import hashlib
import io
import logging
import os
import re
import secrets
from typing import Any, List, Optional, Tuple, Union

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _

from freedec.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from freedec.validators import (
    normalize_and_validate_email_list,
    validate_document_file,
    validate_safe_email,
)

logger = logging.getLogger(__name__)

CHUNK_SIZE: int = 64 * 1024  # 64 KB para lectura segura por bloques anti-DoS (OWASP A04)
HASH_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
GENERIC_ACCESS_MESSAGE: str = _(
    "Si los datos indicados corresponden a un documento activo y una dirección de correo "
    "autorizada, recibirá en breves momentos un código de verificación (OTP) en su buzón."
)


def calculate_file_sha256(file_obj: Any) -> str:
    """
    Calcula el hash criptográfico SHA-256 de un archivo binario mediante lectura en streaming.
    Preserva y restaura el cursor de lectura del stream.
    """
    hasher = hashlib.sha256()
    original_position = 0

    if hasattr(file_obj, "tell"):
        try:
            original_position = file_obj.tell()
        except (OSError, AttributeError):
            original_position = 0

    if hasattr(file_obj, "seek"):
        file_obj.seek(0)

    if hasattr(file_obj, "chunks"):
        for chunk in file_obj.chunks(CHUNK_SIZE):
            hasher.update(chunk)
    else:
        while True:
            chunk = file_obj.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)

    if hasattr(file_obj, "seek"):
        file_obj.seek(original_position)

    return hasher.hexdigest().lower()


def shred_and_delete_file(file_field: Any) -> bool:
    """
    Función auxiliar de borrado seguro (Zeroization/Shredding):
    Sobrescribe el archivo en disco con bytes aleatorios (os.urandom) antes de
    eliminarlo del sistema de archivos físico, previniendo recuperación forense.
    """
    if not file_field:
        return False

    try:
        path = None
        try:
            path = file_field.path
        except (AttributeError, NotImplementedError, ValueError):
            path = None

        if path and os.path.exists(path):
            file_size = os.path.getsize(path)
            if file_size > 0:
                with open(path, "ba+", buffering=0) as f:
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(path)
            logger.info(f"[FREEDEC AUDIT] Shredding físico completado para: {path}")

        file_field.delete(save=False)
        return True
    except Exception as exc:
        logger.error(f"[FREEDEC ERROR] Fallo durante trituración segura de archivo: {exc}")
        try:
            file_field.delete(save=False)
        except Exception:
            pass
        return False


def get_server_fernet_key() -> bytes:
    """Obtiene y normaliza la clave de servidor FREEDEC_FERNET_KEY en bytes."""
    key = getattr(settings, "FREEDEC_FERNET_KEY", None)
    if not key:
        raise ValueError("settings.FREEDEC_FERNET_KEY no se encuentra configurada.")
    if isinstance(key, str):
        return key.strip().encode("utf-8")
    return key


def reactivate_document(
    document: EncryptedDocument,
    original_file: Any,
    new_emails: Union[List[str], str, Any] = None,
    burn_policy: Optional[str] = None,
    admin_user: Any = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> EncryptedDocument:
    """
    Reactiva un documento existente (consumido o activo) re-cifrándolo con una nueva DEK,
    reemplazando la lista de destinatarios autorizados exclusivamente por los nuevos correos
    y preservando todo el historial previo en DocumentAccessLog.
    """
    validate_document_file(original_file)
    new_hash = calculate_file_sha256(original_file)
    if new_hash != document.file_hash:
        raise ValidationError(
            _("El archivo proporcionado no coincide con el hash SHA-256 del documento original.")
        )

    dek: bytes = Fernet.generate_key()
    fernet_dek = Fernet(dek)

    original_file.seek(0)
    file_bytes = original_file.read()
    encrypted_bytes = fernet_dek.encrypt(file_bytes)

    server_key = get_server_fernet_key()
    server_fernet = Fernet(server_key)
    encrypted_dek_str = server_fernet.encrypt(dek).decode("utf-8")

    # Triturar archivo anterior en disco
    if document.encrypted_file:
        shred_and_delete_file(document.encrypted_file)

    filename = getattr(original_file, "name", document.original_filename) or document.original_filename
    clean_filename = os.path.basename(filename)
    enc_filename = f"{clean_filename}.enc"
    document.encrypted_file.save(enc_filename, ContentFile(encrypted_bytes), save=False)

    normalized_emails = (
        normalize_and_validate_email_list(new_emails) if new_emails is not None else document.allowed_emails
    )
    document.encrypted_dek = encrypted_dek_str
    document.allowed_emails = normalized_emails
    if burn_policy:
        document.burn_policy = burn_policy
    document.is_consumed = False
    document.consumed_by = None
    document.consumed_at = None
    document.consumed_recipients = []
    document.save()

    # Invalidar tokens pendientes previos de este documento
    AccessVerificationToken.objects.filter(document=document, is_used=False).update(is_used=True)

    admin_identifier = (
        getattr(admin_user, "email", None)
        or getattr(admin_user, "username", None)
        or str(admin_user or "admin")
    )
    DocumentAccessLog.objects.create(
        document=document,
        email=admin_identifier,
        action=DocumentAccessLog.Action.REACTIVACION_DOCUMENTO,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    logger.info(
        f"[FREEDEC AUDIT] Documento {document.file_hash[:12]}... reactivado exitosamente por '{admin_identifier}'."
    )
    return document


def upload_and_encrypt_document(
    original_file: Any,
    allowed_emails: Union[List[str], str, Any],
    burn_policy: str = EncryptedDocument.BurnPolicy.FIRST_ACCESS,
    reopen_existing: bool = False,
    admin_user: Any = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> EncryptedDocument:
    """
    Servicio de registro y cifrado desatendido de documentos confidenciales.
    
    Si 'reopen_existing=True' y ya existe un documento con el mismo hash SHA-256,
    se reactiva automáticamente re-cifrando en disco y actualizando destinatarios
    sin duplicar el identificador en base de datos.
    
    Retorna: EncryptedDocument (con atributo '_is_reactivated' indicando si fue reactivación)
    """
    validate_document_file(original_file)

    max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", 50 * 1024 * 1024)
    file_size = getattr(original_file, "size", None)
    if file_size is not None and file_size > max_size:
        raise ValidationError(
            _("El archivo excede el tamaño máximo permitido de %(max_size)s MB.")
            % {"max_size": max_size // (1024 * 1024)}
        )

    normalized_emails = normalize_and_validate_email_list(allowed_emails)
    file_hash = calculate_file_sha256(original_file)

    existing_doc = EncryptedDocument.objects.filter(file_hash=file_hash).first()
    if existing_doc:
        if reopen_existing:
            reactivated = reactivate_document(
                document=existing_doc,
                original_file=original_file,
                new_emails=normalized_emails,
                burn_policy=burn_policy,
                admin_user=admin_user,
                client_ip=client_ip,
                user_agent=user_agent,
            )
            reactivated._is_reactivated = True
            return reactivated
        raise ValidationError(_("Ya existe un documento registrado con este mismo hash SHA-256."))

    dek: bytes = Fernet.generate_key()
    fernet_dek = Fernet(dek)

    original_file.seek(0)
    original_bytes: bytes = original_file.read()
    ciphertext_bytes: bytes = fernet_dek.encrypt(original_bytes)

    server_key = get_server_fernet_key()
    server_fernet = Fernet(server_key)
    encrypted_dek_str: str = server_fernet.encrypt(dek).decode("utf-8")

    filename = getattr(original_file, "name", "documento")
    clean_filename = os.path.basename(filename)
    encrypted_filename = f"{clean_filename}.enc"

    document = EncryptedDocument(
        original_filename=clean_filename,
        file_hash=file_hash,
        encrypted_dek=encrypted_dek_str,
        allowed_emails=normalized_emails,
        burn_policy=burn_policy or EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        is_consumed=False,
    )
    document.encrypted_file.save(encrypted_filename, ContentFile(ciphertext_bytes), save=False)
    document.save()

    logger.info(
        f"[FREEDEC AUDIT] Documento registrado exitosamente: id={document.pk} "
        f"hash={document.file_hash[:12]}... política={document.burn_policy}"
    )
    document._is_reactivated = False
    return document


def request_document_access(
    file_hash: str,
    email: str,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Servicio de solicitud desatendida de acceso a documentos confidenciales.
    Mitigación de enumeración y timing attacks con PBKDF2 simulado.
    """
    clean_hash = (file_hash or "").strip().lower()
    clean_email = (email or "").strip().lower()

    if not HASH_REGEX.match(clean_hash):
        hashlib.pbkdf2_hmac("sha256", clean_email.encode("utf-8"), b"freedec_timing_salt", 100_000)
        return True, GENERIC_ACCESS_MESSAGE

    try:
        normalized_email = validate_safe_email(clean_email)
    except ValidationError:
        hashlib.pbkdf2_hmac("sha256", b"invalid_email", b"freedec_timing_salt", 100_000)
        return True, GENERIC_ACCESS_MESSAGE

    document = EncryptedDocument.objects.filter(file_hash=clean_hash).first()

    if not document:
        hashlib.pbkdf2_hmac("sha256", normalized_email.encode("utf-8"), b"freedec_timing_salt", 100_000)
        return True, GENERIC_ACCESS_MESSAGE

    # Verificación de autorización previa (Mitigación de enumeración y fuga de metadatos)
    if not document.is_email_authorized(normalized_email):
        hashlib.pbkdf2_hmac("sha256", normalized_email.encode("utf-8"), b"freedec_timing_salt", 100_000)
        return True, GENERIC_ACCESS_MESSAGE

    # Caso 1: El documento ya fue consumido por completo (notificar exclusivamente al autorizado)
    if document.is_consumed:
        consumed_at_str = (
            document.consumed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            if document.consumed_at
            else _("fecha no registrada")
        )
        consumed_by_str = document.consumed_by or _("un usuario autorizado")
        
        post_consume_message = (
            f"El documento con huella digital SHA-256 {document.file_hash} ya fue retirado de la pasarela "
            f"el {consumed_at_str} por {consumed_by_str}. Por motivos de seguridad (destrucción tras entrega), "
            f"solicite una copia directamente a dicha dirección."
        )

        try:
            send_mail(
                subject=_("Aviso de Seguridad: Documento ya retirado de la pasarela"),
                message=post_consume_message,
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@freedec.local"),
                recipient_list=[normalized_email],
                fail_silently=True,
            )
        except Exception as exc:
            logger.error(f"[FREEDEC ERROR] No se pudo enviar notificación post-consumo: {exc}")

        DocumentAccessLog.objects.create(
            document=document,
            email=normalized_email,
            action=DocumentAccessLog.Action.INTENTO_POST_CONSUMO,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        return True, GENERIC_ACCESS_MESSAGE

    # Caso 2: Política ALL_RECIPIENTS y el destinatario ya descargó su copia individual
    if (
        document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
        and document.is_email_consumed(normalized_email)
    ):
        DocumentAccessLog.objects.create(
            document=document,
            email=normalized_email,
            action=DocumentAccessLog.Action.INTENTO_POST_CONSUMO,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        doc_name = document.original_filename or f"Documento_{document.file_hash[:8]}"
        try:
            send_mail(
                subject=f"[Freedec] Copia ya descargada: {doc_name}",
                message=(
                    f"Usted ya ha descargado previamente una copia del documento '{doc_name}'. "
                    f"Cada destinatario autorizado dispone de una única descarga permitida."
                ),
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@freedec.local"),
                recipient_list=[normalized_email],
                fail_silently=True,
            )
        except Exception as exc:
            logger.error(f"[FREEDEC ERROR] Fallo al enviar aviso de copia consumida: {exc}")
        return True, GENERIC_ACCESS_MESSAGE

    # Caso 3: Documento activo y correo en lista blanca
    if document.is_email_authorized(normalized_email):
        AccessVerificationToken.objects.filter(
            document=document,
            email=normalized_email,
            is_used=False,
        ).update(is_used=True)

        otp_code = "".join(secrets.choice("0123456789") for _ in range(6))
        expires_at = timezone.now() + timezone.timedelta(minutes=15)

        token = AccessVerificationToken.objects.create(
            document=document,
            email=normalized_email,
            otp_code=otp_code,
            expires_at=expires_at,
            is_used=False,
            failed_attempts=0,
        )

        try:
            redeem_path = reverse("freedec:redeem-otp")
        except Exception:
            redeem_path = "/freedec/canjear/"

        query_params = f"?hash={document.file_hash}&email={normalized_email}"
        redeem_url = f"{base_url.rstrip('/')}{redeem_path}{query_params}" if base_url else f"{redeem_path}{query_params}"

        policy_note = (
            "AVISO DE SEGURIDAD (Destrucción tras acceso de todos): El archivo permanecerá disponible hasta que todos los destinatarios hayan accedido."
            if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
            else "AVISO DE SEGURIDAD (Burn-After-Read): Al primer canje exitoso, el archivo almacenado en disco será destruido físicamente de forma permanente."
        )

        email_subject = _("Código de verificación OTP para documento confidencial - Freedec")
        email_body = (
            f"Ha solicitado el canje del documento confidencial identificado con SHA-256:\n"
            f"{document.file_hash}\n\n"
            f"Su código de verificación OTP de un solo uso es:\n"
            f"{otp_code}\n\n"
            f"Validez estricta: 15 minutos.\n"
            f"Intentos máximos permitidos: 3 intentos.\n\n"
            f"Puede acceder directamente para canjearlo en el siguiente enlace:\n"
            f"{redeem_url}\n\n"
            f"{policy_note}"
        )

        try:
            send_mail(
                subject=email_subject,
                message=email_body,
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@freedec.local"),
                recipient_list=[normalized_email],
                fail_silently=False,
            )
        except Exception as exc:
            logger.error(f"[FREEDEC ERROR] Fallo al enviar correo con código OTP: {exc}")

        DocumentAccessLog.objects.create(
            document=document,
            email=normalized_email,
            action=DocumentAccessLog.Action.OTP_ENVIADO,
            ip_address=client_ip,
            user_agent=user_agent,
        )
        return True, GENERIC_ACCESS_MESSAGE

    # Correo no autorizado: PBKDF2 simulado y respuesta neutra
    hashlib.pbkdf2_hmac("sha256", normalized_email.encode("utf-8"), b"freedec_timing_salt", 100_000)
    return True, GENERIC_ACCESS_MESSAGE


def consume_document_with_otp(
    file_hash: str,
    email: str,
    entered_otp: str,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Tuple[bool, bytes, str, str]:
    """
    Servicio de canje, descifrado en memoria y gestión de política destructiva por OTP.
    Aplica política BurnPolicy.FIRST_ACCESS o BurnPolicy.ALL_RECIPIENTS.
    """
    clean_hash = (file_hash or "").strip().lower()
    clean_email = (email or "").strip().lower()
    clean_otp = (entered_otp or "").strip()

    token = (
        AccessVerificationToken.objects.select_related("document")
        .filter(
            document__file_hash__iexact=clean_hash,
            email__iexact=clean_email,
            is_used=False,
        )
        .order_by("-created_at")
        .first()
    )

    if not token or not token.is_valid():
        return False, b"", "", _("Código inválido o expirado.")

    document = token.document

    if document.is_consumed:
        token.is_used = True
        token.save(update_fields=["is_used"])
        return False, b"", "", _("El documento ya fue canjeado y destruido previamente.")

    if (
        document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
        and document.is_email_consumed(token.email)
    ):
        token.is_used = True
        token.save(update_fields=["is_used"])
        return (
            False,
            b"",
            "",
            _("Usted ya ha descargado previamente una copia de este documento. Cada destinatario autorizado dispone de una única descarga permitida."),
        )

    is_match = secrets.compare_digest(token.otp_code.encode("utf-8"), clean_otp.encode("utf-8"))

    if not is_match:
        token.register_failed_attempt()
        if token.failed_attempts >= 3:
            DocumentAccessLog.objects.create(
                document=document,
                email=token.email,
                action=DocumentAccessLog.Action.OTP_INVALIDO_BLOQUEADO,
                ip_address=client_ip,
                user_agent=user_agent,
            )
            return (
                False,
                b"",
                "",
                _("Código inválido. Ha superado el número máximo de 3 intentos y el acceso ha sido bloqueado."),
            )
        else:
            remaining = 3 - token.failed_attempts
            return (
                False,
                b"",
                "",
                _("Código de verificación incorrecto. Intentos restantes: %(remaining)d.")
                % {"remaining": remaining},
            )

    try:
        with transaction.atomic():
            token.is_used = True
            token.save(update_fields=["is_used"])

            server_key = get_server_fernet_key()
            server_fernet = Fernet(server_key)
            dek_bytes = server_fernet.decrypt(document.encrypted_dek.encode("utf-8"))

            if not document.encrypted_file:
                return False, b"", "", _("El archivo cifrado no está disponible en el servidor.")

            document.encrypted_file.seek(0)
            encrypted_file_bytes = document.encrypted_file.read()

            dek_fernet = Fernet(dek_bytes)
            decrypted_bytes = dek_fernet.decrypt(encrypted_file_bytes)

            consumed_list = list(document.consumed_recipients or [])
            if token.email not in [e.strip().lower() for e in consumed_list if isinstance(e, str)]:
                consumed_list.append(token.email)
            document.consumed_recipients = consumed_list

            should_burn = False
            if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
                if document.are_all_recipients_consumed():
                    should_burn = True
                    document.consumed_by = f"todos los destinatarios autorizados ({len(consumed_list)}/{len(document.allowed_emails)})"
                else:
                    should_burn = False
                    document.consumed_by = f"Parcial: {len(consumed_list)}/{len(document.allowed_emails)}"
            else:
                should_burn = True
                document.consumed_by = token.email

            if should_burn:
                shred_and_delete_file(document.encrypted_file)
                document.is_consumed = True
                document.consumed_at = timezone.now()
                document.save(update_fields=["is_consumed", "consumed_by", "consumed_at", "consumed_recipients"])
                log_action = DocumentAccessLog.Action.DESCIFRADO_EXITOSO_BURN
                logger.info(
                    f"[FREEDEC AUDIT] Destrucción física final completada para documento {document.file_hash[:12]}... por {token.email}."
                )
            else:
                document.save(update_fields=["consumed_by", "consumed_recipients"])
                log_action = DocumentAccessLog.Action.DESCIFRADO_PARCIAL_PRESERVADO
                logger.info(
                    f"[FREEDEC AUDIT] Descifrado parcial preservado para documento {document.file_hash[:12]}... por {token.email}."
                )

            DocumentAccessLog.objects.create(
                document=document,
                email=token.email,
                action=log_action,
                ip_address=client_ip,
                user_agent=user_agent,
            )

        return True, decrypted_bytes, document.original_filename, _("Documento descifrado con éxito.")

    except Exception as exc:
        logger.error(f"[FREEDEC ERROR] Fallo durante descifrado y canje del documento: {exc}")
        return False, b"", "", _("Se produjo un error al procesar el descifrado del documento.")


def admin_decrypt_document(
    document: EncryptedDocument,
    admin_user: Any = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Tuple[bool, bytes, str, str]:
    """
    Descarga de auditoría administrativa preservada:
    Permite al personal de auditoría descargar una copia descifrada mientras el documento
    NO haya sido consumido, SIN destruir el archivo ni marcar is_consumed = True.
    """
    if document.is_consumed:
        return False, b"", "", _("El documento ya ha sido consumido y destruido del servidor.")

    if not document.encrypted_file:
        return False, b"", "", _("El archivo cifrado no está disponible.")

    try:
        server_key = get_server_fernet_key()
        server_fernet = Fernet(server_key)
        dek_bytes = server_fernet.decrypt(document.encrypted_dek.encode("utf-8"))

        document.encrypted_file.seek(0)
        ciphertext = document.encrypted_file.read()

        dek_fernet = Fernet(dek_bytes)
        decrypted_bytes = dek_fernet.decrypt(ciphertext)

        admin_identifier = (
            getattr(admin_user, "email", None)
            or getattr(admin_user, "username", None)
            or str(admin_user or "admin_auditor")
        )

        DocumentAccessLog.objects.create(
            document=document,
            email=admin_identifier,
            action=DocumentAccessLog.Action.ADMIN_DESCARGA_PRESERVADA,
            ip_address=client_ip,
            user_agent=user_agent,
        )

        logger.info(
            f"[FREEDEC AUDIT] Descarga administrativa preservada realizada por '{admin_identifier}' "
            f"para documento {document.file_hash[:12]}..."
        )
        return True, decrypted_bytes, document.original_filename, _("Descarga de auditoría completada.")

    except Exception as exc:
        logger.error(f"[FREEDEC ERROR] Error en descarga de auditoría administrativa: {exc}")
        return False, b"", "", _("Error al descifrar el documento para auditoría.")


class DocumentManagementService:
    """
    Clase de servicio unificada para operaciones sobre documentos confidenciales.
    """

    def upload_and_encrypt_document(
        self,
        original_file: Any,
        allowed_emails: Union[List[str], str, Any],
        burn_policy: str = EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        reopen_existing: bool = False,
        admin_user: Any = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs: Any,
    ) -> EncryptedDocument:
        return upload_and_encrypt_document(
            original_file=original_file,
            allowed_emails=allowed_emails,
            burn_policy=burn_policy,
            reopen_existing=reopen_existing,
            admin_user=admin_user,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def reactivate_document(
        self,
        document: EncryptedDocument,
        original_file: Any,
        new_emails: Union[List[str], str, Any] = None,
        burn_policy: Optional[str] = None,
        admin_user: Any = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> EncryptedDocument:
        return reactivate_document(
            document=document,
            original_file=original_file,
            new_emails=new_emails,
            burn_policy=burn_policy,
            admin_user=admin_user,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def request_document_access(
        self,
        file_hash: str,
        email: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[bool, str]:
        return request_document_access(
            file_hash=file_hash,
            email=email,
            client_ip=client_ip,
            user_agent=user_agent,
            base_url=base_url,
        )

    def consume_document_with_otp(
        self,
        file_hash: str,
        email: str,
        entered_otp: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, bytes, str, str]:
        return consume_document_with_otp(
            file_hash=file_hash,
            email=email,
            entered_otp=entered_otp,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def admin_decrypt_document(
        self,
        document: EncryptedDocument,
        admin_user: Any = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, bytes, str, str]:
        return admin_decrypt_document(
            document=document,
            admin_user=admin_user,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def shred_and_delete_file(self, file_field: Any) -> bool:
        return shred_and_delete_file(file_field)
