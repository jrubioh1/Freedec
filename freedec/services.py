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
    "Si los datos indicados corresponden a un documento disponible y una dirección de correo "
    "autorizada, recibirá en breve un código de verificación en su buzón."
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
    new_description: Optional[str] = None,
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
    if new_description is not None:
        document.description = new_description
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
    description: Optional[str] = None,
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
                new_description=description,
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

    doc_kwargs = {
        "original_filename": clean_filename,
        "file_hash": file_hash,
        "encrypted_dek": encrypted_dek_str,
        "allowed_emails": normalized_emails,
        "burn_policy": burn_policy or EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        "is_consumed": False,
    }
    if description is not None:
        doc_kwargs["description"] = description

    document = EncryptedDocument(**doc_kwargs)
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
        doc_name = document.original_filename or f"Documento_{document.file_hash[:8]}"
        desc_part = f"• Descripción: {document.description}\n" if document.description else ""
        
        post_consume_message = (
            f"Estimado/a usuario/a,\n\n"
            f"Le informamos de que el documento solicitado ya fue retirado de la pasarela el {consumed_at_str} por {consumed_by_str} "
            f"y no se encuentra disponible para su descarga.\n\n"
            f"DATOS DEL DOCUMENTO:\n"
            f"• Archivo: {doc_name}\n"
            f"{desc_part}"
            f"• Identificador (SHA-256): {document.file_hash}\n\n"
            f"Por motivos de confidencialidad y seguridad, el documento deja de estar accesible en la plataforma tras su entrega. "
            f"Si precisa una copia, por favor solicítela directamente a dicha dirección.\n\n"
            f"Atentamente,\n"
            f"Servicio de Entrega Segura - Freedec"
        )

        try:
            send_mail(
                subject=_("Información sobre su solicitud: Documento '%(filename)s'")
                % {"filename": doc_name},
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
        desc_part = f"• Descripción: {document.description}\n" if document.description else ""
        try:
            send_mail(
                subject=_("Aviso: Copia ya descargada de '%(filename)s'") % {"filename": doc_name},
                message=(
                    f"Estimado/a usuario/a,\n\n"
                    f"Le comunicamos que su dirección de correo ya ha descargado previamente este documento.\n\n"
                    f"DATOS DEL DOCUMENTO:\n"
                    f"• Archivo: {doc_name}\n"
                    f"{desc_part}"
                    f"• Identificador (SHA-256): {document.file_hash}\n\n"
                    f"Por motivos de seguridad, cada destinatario autorizado dispone de una única descarga. "
                    f"Si necesita volver a consultar el archivo, por favor revise sus descargas locales o contacte con el remitente.\n\n"
                    f"Atentamente,\n"
                    f"Servicio de Entrega Segura - Freedec"
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
            "El documento permanecerá disponible hasta que todos los destinatarios autorizados hayan completado su descarga."
            if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
            else "Por motivos de seguridad y confidencialidad, el documento dejará de estar disponible una vez completada la primera descarga."
        )

        doc_name = document.original_filename or f"Documento_{document.file_hash[:8]}"
        desc_part = f"• Descripción: {document.description}\n" if document.description else ""
        email_subject = _("Código de verificación para '%(filename)s' - Freedec") % {"filename": doc_name}
        email_body = (
            f"Estimado/a usuario/a,\n\n"
            f"Ha solicitado el acceso al siguiente documento:\n"
            f"• Archivo: {doc_name}\n"
            f"{desc_part}"
            f"• Identificador (SHA-256):\n"
            f"  {document.file_hash}\n\n"
            f"Su código de verificación temporal es:\n"
            f"{otp_code}\n\n"
            f"Validez: 15 minutos (máximo 3 intentos permitidos).\n\n"
            f"Puede acceder directamente a la descarga a través del siguiente enlace:\n"
            f"{redeem_url}\n\n"
            f"Aviso de seguridad:\n"
            f"{policy_note}\n\n"
            f"Atentamente,\n"
            f"Servicio de Entrega Segura - Freedec"
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


def generate_corporate_email_text(document: EncryptedDocument, base_url: Optional[str] = None) -> str:
    """
    Genera el texto formal para notificar al destinatario,
    incluyendo nombre del archivo, descripción, identificador SHA-256 e instrucciones de acceso.
    """
    url_root = (base_url or getattr(settings, "FREEDEC_BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
    solicitar_url = f"{url_root}/freedec/solicitar/?hash={document.file_hash}"
    policy_desc = (
        "El documento permanecerá disponible en la plataforma hasta que todos los destinatarios autorizados hayan completado su descarga."
        if document.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS
        else "Por motivos de seguridad y confidencialidad, el documento dejará de estar disponible una vez completada la primera descarga."
    )
    desc_part = f"\n• Descripción: {document.description}" if document.description else ""

    return (
        f"Estimado/a destinatario/a,\n\n"
        f"Le informamos de que se ha puesto a su disposición el siguiente documento para su descarga segura a través de Freedec:\n\n"
        f"DATOS DEL DOCUMENTO:\n"
        f"• Nombre del archivo: {document.original_filename}"
        f"{desc_part}\n"
        f"• Identificador (Hash SHA-256):\n"
        f"  {document.file_hash}\n\n"
        f"INSTRUCCIONES DE DESCARGA:\n"
        f"1. Acceda al siguiente enlace para iniciar la descarga:\n"
        f"   {solicitar_url}\n"
        f"2. Indique su dirección de correo electrónico para recibir un código de verificación temporal.\n"
        f"3. Introduzca el código recibido en la pasarela para descargar el archivo.\n\n"
        f"AVISO DE SEGURIDAD:\n"
        f"{policy_desc}\n\n"
        f"Atentamente,\n"
        f"Servicio de Entrega Segura - Freedec"
    )


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
        return False, b"", "", _("El código de verificación no es válido o ha expirado.")

    document = token.document

    if document.is_consumed:
        token.is_used = True
        token.save(update_fields=["is_used"])
        return False, b"", "", _("El documento ya no se encuentra disponible para su descarga.")

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
            _("Usted ya ha descargado este documento con anterioridad. Cada destinatario dispone de un único acceso."),
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
                _("Ha superado el número máximo de intentos permitidos. El acceso ha sido bloqueado por seguridad."),
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
        description: Optional[str] = None,
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
            description=description,
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
        new_description: Optional[str] = None,
        admin_user: Any = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> EncryptedDocument:
        return reactivate_document(
            document=document,
            original_file=original_file,
            new_emails=new_emails,
            burn_policy=burn_policy,
            new_description=new_description,
            admin_user=admin_user,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def generate_corporate_email_text(
        self,
        document: EncryptedDocument,
        base_url: Optional[str] = None,
    ) -> str:
        return generate_corporate_email_text(document=document, base_url=base_url)

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
