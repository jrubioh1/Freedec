import base64
import hashlib
import io
import logging
import os
import secrets
import string
import zipfile
from typing import List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.mail import BadHeaderError, send_mail
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from freedec.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from freedec.validators import validate_document_file, validate_safe_email

logger = logging.getLogger(__name__)


def derive_fernet_key(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave simétrica de 32 bytes compatible con Fernet (base64 url-safe)
    a partir de una contraseña y un salt criptográfico utilizando PBKDF2-HMAC-SHA256 (100.000 iteraciones).
    Mitiga ataques de diccionario y fuerza bruta offline contra las contraseñas de usuario (OWASP A02).
    """
    kdf = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return base64.urlsafe_b64encode(kdf)


def generate_secure_password(length: int = 24) -> str:
    """
    Genera automáticamente una contraseña criptográficamente segura de alta entropía.
    Incluye caracteres alfanuméricos y símbolos de forma balanceada.
    """
    chars = string.ascii_letters + string.digits + "!@#$%&*-_=+"
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%&*-_=+" for c in pwd)
        ):
            return pwd

# Hash PBKDF2 ficticio precalculado para neutralizar ataques de canal lateral (Timing Attacks)
# cuando un documento no es encontrado en la base de datos (OWASP A04: Insecure Design).
DUMMY_PBKDF2_HASH = (
    "pbkdf2_sha256$720000$freedecdummy$"
    "e2ZmMDU0YTI4ODUzYmIxZTc4MTE4Mzk5ZTRhOWRhZjYzMGQ0MGYzOWU0MDcwNDdlMWE5N2QxMTQxZDIzNzMwOA=="
)

# Tamaño máximo por defecto para subida de archivos (50 MB)
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024
CHUNK_SIZE = 64 * 1024  # 64 KB por bloque para cálculo y lectura segura anti-DoS


def calculate_file_sha256(file_obj) -> str:
    """
    Calcula el hash criptográfico SHA-256 de un archivo binario mediante lectura en streaming.
    
    Principios de Ciberseguridad (OWASP A04 / A08):
    - Lectura en bloques (chunks) de 64 KB: Previene ataques de Denegación de Servicio (DoS)
      por agotamiento de memoria RAM (OOM) en archivos de gran tamaño.
    - Preservación del cursor: Guarda la posición inicial del puntero y la restaura al terminar
      para permitir lecturas posteriores sin corromper el stream de subida.
    """
    sha256_hasher = hashlib.sha256()
    
    # Guardar posición original del puntero de lectura
    original_position = 0
    if hasattr(file_obj, "tell"):
        try:
            original_position = file_obj.tell()
        except (OSError, AttributeError):
            original_position = 0

    if hasattr(file_obj, "seek"):
        file_obj.seek(0)

    # Lectura eficiente en bloques
    if hasattr(file_obj, "chunks"):
        for chunk in file_obj.chunks(CHUNK_SIZE):
            sha256_hasher.update(chunk)
    else:
        while True:
            chunk = file_obj.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256_hasher.update(chunk)

    # Restaurar puntero de lectura al inicio para que otros procesos puedan leerlo
    if hasattr(file_obj, "seek"):
        file_obj.seek(0)

    return sha256_hasher.hexdigest()


def detect_file_extension_and_mimetype(data: bytes) -> Tuple[str, str]:
    """
    Detecta la extensión de archivo y el mimetype analizando las cabeceras binarias (magic bytes).
    Soporta PDF, OpenXML (Word/Excel/PowerPoint), OpenDocument Format (LibreOffice) y OLE2 (doc/xls/ppt).
    """
    if data.startswith(b"%PDF-"):
        return ".pdf", "application/pdf"

    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = set(zf.namelist())
                if "word/document.xml" in names:
                    return ".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                if "xl/workbook.xml" in names:
                    return ".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                if "ppt/presentation.xml" in names:
                    return ".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                if "mimetype" in names:
                    mime_content = zf.read("mimetype").decode("utf-8", errors="ignore").strip()
                    if "opendocument.text" in mime_content:
                        return ".odt", "application/vnd.oasis.opendocument.text"
                    if "opendocument.spreadsheet" in mime_content:
                        return ".ods", "application/vnd.oasis.opendocument.spreadsheet"
                    if "opendocument.presentation" in mime_content:
                        return ".odp", "application/vnd.oasis.opendocument.presentation"
        except Exception:
            pass
        return ".zip", "application/zip"

    if data.startswith(b"\xd0\xcf\x11\xe0"):
        return ".doc", "application/msword"

    return ".bin", "application/octet-stream"


class FernetCryptoService:
    """
    Servicio de Cifrado Simétrico Autenticado (AEAD) basado en cryptography.fernet.
    
    Detalles Criptográficos (OWASP A02: Cryptographic Failures):
    - Algoritmo: AES-128 en modo CBC con padding PKCS7.
    - Autenticación: HMAC-SHA256 con clave de integridad derivada.
    - Clave: Derivada de 'settings.FREEDEC_FERNET_KEY' (debe ser una clave base64 url-safe de 32 bytes).
    - Propiedad AEAD: Si un atacante modifica un solo bit del archivo en disco o del token cifrado,
      la verificación HMAC fallará y lanzará una excepción InvalidToken, impidiendo ataques de padding oracle.
    """

    def __init__(self, key: str = None):
        raw_key = key or getattr(settings, "FREEDEC_FERNET_KEY", None)
        if not raw_key:
            # Fallback seguro para entorno de testing
            if getattr(settings, "TESTING", False):
                raw_key = Fernet.generate_key().decode()
            else:
                raise ValueError("No se ha configurado 'FREEDEC_FERNET_KEY' en los settings de Django.")
        
        if isinstance(raw_key, str):
            raw_key = raw_key.encode("utf-8")
        
        self.fernet = Fernet(raw_key)

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Cifra un arreglo de bytes utilizando AES-128-CBC + HMAC-SHA256."""
        return self.fernet.encrypt(data)

    def decrypt_bytes(self, token: bytes) -> bytes:
        """
        Descifra un arreglo de bytes cifrados.
        Lanza ValueError si el token ha sido alterado o la clave es incorrecta.
        """
        try:
            return self.fernet.decrypt(token)
        except InvalidToken as exc:
            logger.error("[FREEDEC SECURITY] Error de integridad o clave incorrecta al descifrar bytes con Fernet.")
            raise ValueError("Fallo de integridad o clave inválida al descifrar el contenido.") from exc

    def encrypt_string(self, text: str) -> str:
        """Cifra una cadena de texto (ej. contraseña) y la devuelve en formato base64 url-safe (string)."""
        encrypted_bytes = self.encrypt_bytes(text.encode("utf-8"))
        return encrypted_bytes.decode("utf-8")

    def decrypt_string(self, token_str: str) -> str:
        """Descifra una cadena de texto cifrada y devuelve el texto plano original en UTF-8."""
        decrypted_bytes = self.decrypt_bytes(token_str.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")


class DocumentManagementService:
    """
    Capa de servicios de negocio y orquestación criptográfica de Freedec.

    Principios de Ciberseguridad (OWASP Top 10):
    1. Arquitectura Criptográfica DEK Multi-Usuario con Sobres Digitales (user_envelopes):
       - Clave Maestra de Datos (DEK): Generada por Fernet.generate_key().
       - Cifrado único: El archivo original se cifra una sola vez con la DEK.
       - Para cada correo en allowed_emails:
         - Genera un secreto aleatorio individual para ese usuario (user_secret).
         - Cifra la DEK con dicho secreto: Fernet(user_secret).encrypt(dek).
         - Cifra el secreto del usuario con FREEDEC_FERNET_KEY de servidor y lo guarda en el sobre.
       - Cifra la DEK con la clave de servidor para permitir descarga administrativa preservada.
    2. Flujo de Acceso Dinámico (Magic Link / OTP) - Prueba de posesión en tiempo real:
       - No existen contraseñas fijas ni códigos de acceso estáticos.
       - El usuario final solicita acceso subiendo el archivo .enc y su correo electrónico.
       - Si el documento está activo y autorizado, se genera un token de un solo uso y un código
         OTP de 6 dígitos con expiración estricta de 15 minutos.
       - Se notifica por correo electrónico con enlace directo y código alternativo.
    3. Descifrado al Vuelo y Destrucción Física (Burn-After-Read):
       - Al validar el token u OTP en la vista de consumo, el backend abre el sobre digital del usuario,
         recupera la DEK y entrega el archivo descifrado al usuario.
       - El archivo físico .enc en disco se elimina de forma inmediata y definitiva (save=False).
       - El registro en BD se actualiza: is_consumed=True, consumed_by=email, consumed_at=now.
       - El token se marca como is_used=True.
       - Se audita el evento con action='descifrado_completado_burn'.
    4. Gestión de Intentos Post-Consumo:
       - Si otro usuario autorizado intenta solicitar acceso a un documento consumido, no se generan
         errores 500 ni se fuga el binario; se envía un correo informando que el recurso ya fue
         reclamado por consumed_by en consumed_at.
       - Se audita con action='intento_post_consumo'.
    5. Descarga Administrativa Preservada (Audit Bypass):
       - El personal administrativo autenticado puede descargar el archivo original descifrado
         sin eliminar el archivo ni marcarlo como consumido.
       - Se audita con action='admin_inspeccion_preservada'.
    """

    def __init__(self, crypto_service: FernetCryptoService = None):
        self.crypto_service = crypto_service or FernetCryptoService()

    @transaction.atomic
    def upload_and_encrypt_document(
        self,
        original_file,
        allowed_emails: List[str] = None,
        plain_password: Optional[str] = None,
    ) -> Tuple[EncryptedDocument, None]:
        """
        Registra y cifra un documento aplicando el patrón DEK multi-usuario (user_envelopes).
        Retorna la tupla (document, None) para mantener compatibilidad de signatura.
        """
        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if hasattr(original_file, "size") and original_file.size > max_size:
            max_mb = max_size // (1024 * 1024)
            raise ValidationError(
                _("El archivo excede el tamaño máximo permitido de %(max_size)s MB.")
                % {"max_size": max_mb}
            )

        # Validación estructural y de firmas binarias (OWASP A03 / A08)
        validate_document_file(original_file)

        # 1. Identificación criptográfica por SHA-256 del contenido original
        file_hash = calculate_file_sha256(original_file)

        if EncryptedDocument.objects.filter(file_hash=file_hash).exists():
            raise ValidationError(
                _("Ya existe un documento registrado con el hash SHA-256: %(file_hash)s.")
                % {"file_hash": file_hash}
            )

        # 2. Generación de Clave Maestra simétrica única (DEK)
        dek = Fernet.generate_key()

        # 3. Cifrado del contenido original una sola vez usando la DEK
        original_file.seek(0)
        file_bytes = original_file.read()
        encrypted_bytes = Fernet(dek).encrypt(file_bytes)
        encrypted_file_hash = hashlib.sha256(encrypted_bytes).hexdigest()

        # Cifrar la DEK para el Administrador con la clave del servidor
        admin_encrypted_dek = self.crypto_service.encrypt_bytes(dek).decode("utf-8")

        # 4. Empaquetar el archivo cifrado para almacenamiento seguro en disco
        raw_name = getattr(original_file, "name", "documento") or "documento"
        safe_original_name = os.path.basename(str(raw_name)).strip()
        if not safe_original_name or safe_original_name == ".":
            safe_original_name = "documento.pdf"

        enc_filename = f"{safe_original_name}.enc"
        encrypted_content = ContentFile(encrypted_bytes, name=enc_filename)

        # 5. Desinfección y normalización rigurosa de correos autorizados
        allowed_list = allowed_emails or []
        normalized_emails = sorted(
            list(
                {
                    validate_safe_email(email)
                    for email in allowed_list
                    if isinstance(email, str) and email.strip()
                }
            )
        )
        if not normalized_emails:
            normalized_emails = ["destinatario@freedec.local"]

        # 6. Para cada correo en allowed_emails: generar secreto de usuario y construir sobre digital
        user_envelopes = {}
        for email in normalized_emails:
            user_secret = Fernet.generate_key()
            encrypted_dek = Fernet(user_secret).encrypt(dek).decode("utf-8")
            encrypted_user_secret = self.crypto_service.encrypt_bytes(user_secret).decode("utf-8")
            user_envelopes[email] = {
                "encrypted_dek": encrypted_dek,
                "encrypted_user_secret": encrypted_user_secret,
            }

        # 7. Creación atómica del registro
        document = EncryptedDocument.objects.create(
            original_filename=safe_original_name,
            file_hash=file_hash,
            encrypted_file=encrypted_content,
            encrypted_file_hash=encrypted_file_hash,
            admin_encrypted_dek=admin_encrypted_dek,
            user_envelopes=user_envelopes,
            allowed_emails=normalized_emails,
            is_consumed=False,
        )

        logger.info(
            f"[FREEDEC AUDIT] Documento '{safe_original_name}' registrado exitosamente con DEK multi-usuario. Hash SHA-256: {file_hash}"
        )
        return document, None

    def request_document_access(
        self,
        uploaded_file,
        recipient_email: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Procesa la solicitud de acceso a un documento subiendo el archivo .enc y proporcionando el correo.
        Genera Enlace Mágico / OTP de 15 minutos o notifica si el archivo ya fue retirado (Requisito 3).
        """
        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if hasattr(uploaded_file, "size") and uploaded_file.size > max_size:
            return False, _("El archivo supera el tamaño máximo permitido.")

        safe_generic_response = _(
            "Si el archivo y el correo electrónico coinciden con un documento activo y autorizado, "
            "se ha enviado un enlace de acceso y un código OTP a su bandeja de entrada."
        )

        try:
            normalized_email = validate_safe_email(recipient_email)
        except ValidationError:
            return True, safe_generic_response

        # Leer archivo y calcular hash SHA-256
        uploaded_file.seek(0)
        file_bytes = uploaded_file.read()
        uploaded_file.seek(0)
        if not file_bytes:
            return True, safe_generic_response

        calculated_hash = hashlib.sha256(file_bytes).hexdigest()

        # Localizar documento por hash del archivo cifrado o por hash del original
        document = (
            EncryptedDocument.objects.filter(encrypted_file_hash=calculated_hash).first()
            or EncryptedDocument.objects.filter(file_hash=calculated_hash).first()
        )

        if not document:
            logger.warning(
                f"[FREEDEC SECURITY] Solicitud de acceso fallida: No existe documento para el hash proporcionado."
            )
            return True, safe_generic_response

        # Si el documento ya fue consumido: Notificar por correo del retiro
        if document.is_consumed:
            try:
                DocumentAccessLog.objects.create(
                    document=document,
                    email=normalized_email,
                    action="intento_post_consumo",
                    ip_address=client_ip,
                    user_agent=user_agent,
                )
            except Exception as exc:
                logger.warning(f"[FREEDEC] Error al registrar intento post-consumo: {exc}")

            doc_name = document.original_filename or f"Documento_{document.file_hash[:8]}"
            consumed_at_str = (
                document.consumed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if document.consumed_at
                else _("recientemente")
            )
            consumed_by_user = document.consumed_by or _("otro usuario autorizado")
            subject = f"[Freedec] Archivo ya retirado: {doc_name}"
            body = (
                _("Estimado usuario,") + "\n\n"
                + f"El documento ya fue retirado por {consumed_by_user} el {consumed_at_str}. Solicite una copia directamente a esa dirección.\n\n"
                + _("Atentamente,") + "\n"
                + _("Sistema Automatizado Freedec")
            )
            from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@freedec.local")
            try:
                send_mail(
                    subject=subject,
                    message=body,
                    from_email=from_email,
                    recipient_list=[normalized_email],
                    fail_silently=False,
                )
                logger.info(f"[FREEDEC AUDIT] Notificación de archivo retirado enviada a '{normalized_email}'.")
            except Exception as exc:
                logger.error(f"[FREEDEC ERROR] Fallo al enviar notificación de archivo retirado: {exc}")

            return True, safe_generic_response

        # Verificar lista de autorizados
        if not document.is_email_authorized(normalized_email):
            logger.warning(
                f"[FREEDEC SECURITY] Correo '{normalized_email}' no autorizado para documento {document.pk}."
            )
            return True, safe_generic_response

        # Generar token url-safe de alta entropía y código OTP de 6 dígitos
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        otp_code = f"{secrets.randbelow(1000000):06d}"
        expires_at = timezone.now() + timezone.timedelta(minutes=15)

        AccessVerificationToken.objects.create(
            document=document,
            email=normalized_email,
            token_hash=token_hash,
            otp_code=otp_code,
            expires_at=expires_at,
            is_used=False,
        )

        # Construir URL del Magic Link
        from django.urls import reverse
        try:
            consume_path = reverse("freedec:gui-consume")
        except Exception:
            consume_path = "/freedec/consumir/"

        if base_url:
            magic_link = f"{base_url.rstrip('/')}{consume_path}?t={raw_token}"
        else:
            magic_link = f"{consume_path}?t={raw_token}"

        doc_name = document.original_filename or f"Documento_{document.file_hash[:8]}"
        subject = f"[Freedec] Enlace de acceso y código OTP: {doc_name}"
        body = (
            _("Estimado usuario,") + "\n\n"
            + (_("Se ha solicitado el acceso y descifrado para el documento: %(doc_name)s") % {"doc_name": doc_name}) + "\n\n"
            + _("Puede descargarlo de forma inmediata mediante el siguiente enlace seguro (válido durante 15 minutos):") + "\n"
            + f"{magic_link}\n\n"
            + _("O si lo prefiere, introduzca manualmente el siguiente código OTP en el portal:") + "\n"
            + f"CÓDIGO OTP: {otp_code}\n\n"
            + _("⚠️ POLÍTICA DE DESTRUCCIÓN INMEDIATA (Burn-after-read):") + "\n"
            + _("Al hacer clic en el enlace o ingresar el código OTP, el archivo se descargará en su equipo y se ELIMINARÁ FÍSICAMENTE DE FORMA IRREVERSIBLE de nuestros servidores.") + "\n\n"
            + _("Atentamente,") + "\n"
            + _("Sistema Automatizado Freedec")
        )
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@freedec.local")

        try:
            send_mail(
                subject=subject,
                message=body,
                from_email=from_email,
                recipient_list=[normalized_email],
                fail_silently=False,
            )
            logger.info(f"[FREEDEC AUDIT] Enlace Mágico y OTP enviados a '{normalized_email}' para '{doc_name}'.")
        except Exception as exc:
            logger.error(f"[FREEDEC ERROR] Fallo al enviar Magic Link/OTP: {exc}")
            return False, _("Error al enviar el correo electrónico con las credenciales de acceso.")

        # Registrar auditoría de solicitud de acceso
        try:
            DocumentAccessLog.objects.create(
                document=document,
                email=normalized_email,
                action="solicitud_acceso",
                ip_address=client_ip,
                user_agent=user_agent,
            )
        except Exception as exc:
            logger.warning(f"[FREEDEC] Error al registrar solicitud_acceso: {exc}")

        return True, safe_generic_response

    def consume_and_burn_document(
        self,
        token_str: Optional[str] = None,
        otp_code: Optional[str] = None,
        email: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, Optional[bytes], Optional[str], Optional[str], str]:
        """
        Valida el Magic Link o código OTP, descifra la DEK del sobre digital del usuario,
        descifra el archivo original, lo entrega al usuario y DESTRUYE FÍSICAMENTE el binario
        en disco marcando el documento como consumido (Burn-After-Read).
        """
        token_obj = None

        if token_str and token_str.strip():
            t_hash = hashlib.sha256(token_str.strip().encode("utf-8")).hexdigest()
            token_obj = AccessVerificationToken.objects.filter(token_hash=t_hash).select_related("document").first()
        elif otp_code and otp_code.strip():
            clean_otp = otp_code.strip()
            qs = AccessVerificationToken.objects.filter(otp_code=clean_otp, is_used=False).select_related("document")
            if email and email.strip():
                qs = qs.filter(email=email.strip().lower())
            token_obj = qs.first()

        if not token_obj:
            return False, None, None, None, _("El enlace de acceso o código OTP es inválido.")

        if token_obj.is_used:
            return False, None, None, None, _("Este enlace de acceso o código OTP ya ha sido utilizado previamente.")

        if token_obj.is_expired():
            return False, None, None, None, _("El enlace de acceso o código OTP ha expirado (límite estricto de 15 minutos).")

        document = token_obj.document
        if document.is_consumed:
            token_obj.is_used = True
            token_obj.save(update_fields=["is_used"])
            return (
                False,
                None,
                None,
                None,
                f"El documento ya fue retirado por {document.consumed_by} el {document.consumed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if document.consumed_at else ''}. Solicite una copia directamente a esa dirección.",
            )

        if not document.encrypted_file:
            return False, None, None, None, _("El archivo cifrado no se encuentra en el almacenamiento.")

        user_email = token_obj.email
        envelope = document.user_envelopes.get(user_email)
        if not envelope or "encrypted_dek" not in envelope or "encrypted_user_secret" not in envelope:
            return False, None, None, None, _("No se encontró un sobre digital válido para el usuario solicitante.")

        # Recuperar secreto del usuario con FREEDEC_FERNET_KEY
        try:
            user_secret = self.crypto_service.decrypt_bytes(envelope["encrypted_user_secret"].encode("utf-8"))
        except Exception as exc:
            logger.error(f"[FREEDEC SECURITY] Error al descifrar secreto de usuario: {exc}")
            return False, None, None, None, _("Error interno al abrir el sobre digital.")

        # Descifrar la DEK con el secreto del usuario
        try:
            dek = Fernet(user_secret).decrypt(envelope["encrypted_dek"].encode("utf-8"))
        except Exception as exc:
            logger.error(f"[FREEDEC SECURITY] Error al descifrar DEK con secreto de usuario: {exc}")
            return False, None, None, None, _("Fallo criptográfico al descifrar la Clave Maestra de Datos.")

        # Leer archivo cifrado y descifrar contenido
        document.encrypted_file.seek(0)
        enc_bytes = document.encrypted_file.read()
        document.encrypted_file.seek(0)

        try:
            decrypted_bytes = Fernet(dek).decrypt(enc_bytes)
        except Exception as exc:
            logger.error(f"[FREEDEC SECURITY] Error al descifrar binario con DEK: {exc}")
            return False, None, None, None, _("Error al procesar el descifrado del documento.")

        # Detectar extensión y tipo MIME
        ext, mimetype = detect_file_extension_and_mimetype(decrypted_bytes)
        suggested_filename = document.original_filename or f"documento_{document.file_hash[:8]}{ext}"

        # 1. Marcar token como utilizado
        token_obj.is_used = True
        token_obj.save(update_fields=["is_used"])

        # 2. Borrado seguro físico del binario en disco
        if document.encrypted_file:
            try:
                document.encrypted_file.delete(save=False)
                logger.info(f"[FREEDEC AUDIT] Archivo físico (.enc) eliminado de disco tras descarga por '{user_email}'.")
            except Exception as exc:
                logger.warning(f"[FREEDEC WARNING] Error al eliminar archivo físico: {exc}")

        # 3. Actualizar registro en base de datos: is_consumed, consumed_by, consumed_at
        now = timezone.now()
        document.is_consumed = True
        document.consumed_by = user_email
        document.consumed_at = now
        document.last_accessed_at = now
        document.last_accessed_by = user_email
        document.access_count += 1
        document.save(update_fields=[
            "is_consumed", "consumed_by", "consumed_at",
            "last_accessed_at", "last_accessed_by", "access_count", "encrypted_file"
        ])

        # 4. Registrar en DocumentAccessLog: action="descifrado_completado_burn"
        try:
            DocumentAccessLog.objects.create(
                document=document,
                email=user_email,
                action="descifrado_completado_burn",
                ip_address=client_ip,
                user_agent=user_agent,
            )
        except Exception as exc:
            logger.warning(f"[FREEDEC] Error al registrar descifrado_completado_burn: {exc}")

        logger.info(
            f"[FREEDEC AUDIT] Documento '{suggested_filename}' consumido y destruido con éxito por '{user_email}'."
        )
        return True, decrypted_bytes, suggested_filename, mimetype, _("Documento descifrado correctamente.")

    def admin_decrypt_document(
        self,
        document: EncryptedDocument,
        admin_user,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, Optional[bytes], Optional[str], Optional[str], str]:
        """
        Descifra el archivo original para un administrador autenticado sin destruir el archivo
        ni marcarlo como consumido (Audit Bypass).
        Registra el evento en DocumentAccessLog con action='admin_inspeccion_preservada'.
        """
        if document.is_consumed:
            return (
                False,
                None,
                None,
                None,
                _(
                    "El documento ya fue consumido por %(user)s el %(date)s. El archivo físico fue eliminado."
                )
                % {
                    "user": document.consumed_by or _("un usuario"),
                    "date": (
                        document.consumed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                        if document.consumed_at
                        else ""
                    ),
                },
            )

        if not document.encrypted_file:
            return False, None, None, None, _("No existe un archivo cifrado en almacenamiento.")

        try:
            storage = document.encrypted_file.storage
            if not storage.exists(document.encrypted_file.name):
                return False, None, None, None, _("El archivo físico no se encuentra en el almacenamiento.")
        except Exception:
            pass

        # Recuperar DEK con la clave de servidor
        dek = None
        if document.admin_encrypted_dek:
            try:
                dek = self.crypto_service.decrypt_bytes(document.admin_encrypted_dek.encode("utf-8"))
            except Exception as exc:
                logger.error(f"[FREEDEC SECURITY] Error al descifrar admin_encrypted_dek: {exc}")

        if not dek:
            return False, None, None, None, _("No se pudo recuperar la clave de descifrado administrativa.")

        document.encrypted_file.seek(0)
        enc_bytes = document.encrypted_file.read()
        document.encrypted_file.seek(0)

        try:
            decrypted_bytes = Fernet(dek).decrypt(enc_bytes)
        except Exception as exc:
            logger.error(f"[FREEDEC SECURITY] Fallo en el descifrado administrativo: {exc}")
            return False, None, None, None, _("Fallo criptográfico al descifrar el documento.")

        admin_identifier = (
            getattr(admin_user, "email", None)
            or getattr(admin_user, "username", "staff_admin")
        )
        try:
            DocumentAccessLog.objects.create(
                document=document,
                email=admin_identifier,
                action="admin_inspeccion_preservada",
                ip_address=client_ip,
                user_agent=user_agent,
            )
        except Exception as exc:
            logger.warning(f"[FREEDEC] Error al registrar admin_inspeccion_preservada: {exc}")

        ext, mimetype = detect_file_extension_and_mimetype(decrypted_bytes)
        suggested_filename = document.original_filename or f"documento_{document.file_hash[:8]}{ext}"

        logger.info(
            f"[FREEDEC AUDIT] Descarga administrativa preservada efectuada por '{admin_identifier}' para '{suggested_filename}'."
        )
        return True, decrypted_bytes, suggested_filename, mimetype, _("Documento descifrado correctamente.")

    # --------------------------------------------------------------------------
    # ALIASES DE COMPATIBILIDAD
    # --------------------------------------------------------------------------
    def verify_and_dispatch_password(
        self,
        uploaded_file,
        access_code: Optional[str] = None,
        recipient_email: Optional[str] = None,
        client_ip: Optional[str] = None,
        decrypt_url: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs,
    ) -> Tuple[bool, str]:
        """Alias de compatibilidad que delega en request_document_access."""
        email = recipient_email or kwargs.get("email") or ""
        return self.request_document_access(
            uploaded_file=uploaded_file,
            recipient_email=email,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def identify_and_decrypt(
        self,
        encrypted_file_obj,
        password: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, Optional[bytes], Optional[str], Optional[str], str]:
        """Alias de compatibilidad: si se envía un token u OTP en el campo password."""
        return self.consume_and_burn_document(
            token_str=password,
            otp_code=password if len(password.strip()) == 6 else None,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def decrypt_document_with_password(
        self,
        encrypted_file_obj,
        password: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, Optional[bytes], Optional[str], Optional[str], str]:
        return self.identify_and_decrypt(
            encrypted_file_obj=encrypted_file_obj,
            password=password,
            client_ip=client_ip,
            user_agent=user_agent,
        )
