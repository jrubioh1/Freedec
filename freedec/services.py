import hashlib
import io
import logging
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

from freedec.models import EncryptedDocument
from freedec.validators import validate_document_file, validate_safe_email

logger = logging.getLogger(__name__)


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
    Capa de servicios de negocio y orquestación de seguridad de Freedec.
    
    Gestiona el ciclo de vida seguro bajo los principios OWASP Top 10:
    1. Registro administrativo: validación profunda de formatos (PDF/LibreOffice/MS Office),
       cálculo de hash SHA-256, cifrado en reposo, generación de secreto Zero-Knowledge
       y almacenamiento transaccional.
    2. Verificación y despacho: cálculo de hash en runtime, validación en tiempo constante,
       comprobación de lista blanca y envío seguro por correo electrónico anti-CRLF.
    """

    def __init__(self, crypto_service: FernetCryptoService = None):
        self.crypto_service = crypto_service or FernetCryptoService()

    @transaction.atomic
    def upload_and_encrypt_document(
        self,
        original_file,
        plain_password: Optional[str] = None,
        allowed_emails: List[str] = None,
    ) -> Tuple[EncryptedDocument, str]:
        """
        Flujo de subida y protección de documento por parte de un administrador.
        
        Pasos de Seguridad:
        1. Valida el tamaño y formato de archivo (PDF, LibreOffice, MS Office) mediante Magic Bytes.
        2. Calcula el hash SHA-256 unívoco del archivo original.
        3. Verifica que no exista un documento registrado con el mismo hash.
        4. Cifra todo el contenido binario del archivo usando AES/Fernet antes de escribir en disco.
        5. Genera un access_code de alta entropía (32 bytes url-safe = 256 bits de entropía).
        6. Almacena el hash PBKDF2 del access_code (Zero-Knowledge: la BD nunca conoce el código original).
        7. Autogenera la contraseña de alta entropía si no se suministra una, y la cifra con Fernet.
        8. Desinfecta y normaliza la lista de correos autorizados (anti-CRLF).
        9. Retorna la instancia creada (con 'generated_password' accesible) y el access_code en texto plano.
        """
        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if hasattr(original_file, "size") and original_file.size > max_size:
            raise ValidationError(
                f"El archivo excede el tamaño máximo permitido de {max_size // (1024 * 1024)} MB."
            )

        # Validación estructural y de firmas binarias (OWASP A03 / A08)
        validate_document_file(original_file)

        # 1. Identificación criptográfica por SHA-256 del contenido original
        file_hash = calculate_file_sha256(original_file)

        if EncryptedDocument.objects.filter(file_hash=file_hash).exists():
            raise ValidationError(
                f"Ya existe un documento registrado con el hash SHA-256: {file_hash}."
            )

        # 2. Lectura y cifrado del archivo original
        original_file.seek(0)
        file_bytes = original_file.read()
        encrypted_bytes = self.crypto_service.encrypt_bytes(file_bytes)

        # 3. Empaquetar el archivo cifrado para almacenamiento seguro en disco
        # Se utiliza el hash SHA-256 como nombre para neutralizar cualquier vector de Path Traversal
        encrypted_content = ContentFile(encrypted_bytes, name=f"{file_hash}.enc")

        # 4. Generación de código de acceso de alta entropía (Zero-Knowledge)
        raw_access_code = secrets.token_urlsafe(32)
        hashed_access_code = make_password(raw_access_code)

        # 5. Generación automática o uso de contraseña provista, y cifrado con Fernet
        if plain_password and plain_password.strip():
            effective_password = plain_password.strip()
        else:
            effective_password = generate_secure_password(24)

        encrypted_pwd = self.crypto_service.encrypt_string(effective_password)

        # 6. Desinfección y normalización rigurosa de correos electrónicos (anti-CRLF)
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

        # 7. Creación atómica del registro
        document = EncryptedDocument.objects.create(
            file_hash=file_hash,
            encrypted_file=encrypted_content,
            access_code=hashed_access_code,
            encrypted_password=encrypted_pwd,
            allowed_emails=normalized_emails,
        )
        document.generated_password = effective_password

        logger.info(f"[FREEDEC AUDIT] Documento registrado exitosamente. Hash SHA-256: {file_hash}")
        return document, raw_access_code

    def verify_and_dispatch_password(
        self,
        uploaded_file,
        access_code: str,
        recipient_email: str,
    ) -> Tuple[bool, str]:
        """
        Flujo de verificación pública y envío automatizado de la clave descifrada.
        
        Medidas de Ciberseguridad Aplicadas (OWASP Top 10):
        1. Validación de Formatos: Comprueba magic bytes para asegurar que sea PDF/LibreOffice/Office.
        2. Identificación dinámica: Se calcula el SHA-256 del archivo que sube el usuario final en runtime.
        3. Mitigación de Timing Attacks & Enumeración de Documentos (OWASP A04):
           Si el archivo no coincide con ningún registro, se ejecuta un hash simulado para igualar el
           tiempo de respuesta y se devuelve un mensaje de éxito genérico/neutro.
        4. Verificación de Código de Acceso: Compara el código contra el hash PBKDF2 almacenado.
        5. Verificación de Autorización: Confirma que el correo esté en la lista blanca 'allowed_emails'.
        6. Despacho Exclusivo por Correo: La clave recuperada NUNCA se expone en la respuesta HTTP;
           se transmite únicamente a la dirección de correo autorizada, sanitizada contra CRLF.
        """
        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if hasattr(uploaded_file, "size") and uploaded_file.size > max_size:
            return False, "El archivo supera el tamaño máximo permitido."

        # Respuesta unificada de seguridad para mitigar enumeración de archivos y usuarios
        safe_generic_response = (
            "Si el archivo, el código de acceso y el correo electrónico coinciden con los "
            "registros autorizados, la clave de descifrado ha sido enviada a su buzón."
        )

        # Validación de correo
        try:
            normalized_email = validate_safe_email(recipient_email)
        except ValidationError:
            check_password(access_code, DUMMY_PBKDF2_HASH)
            return True, safe_generic_response

        # Detección de tipo de archivo: ¿Es un archivo .enc cifrado o el archivo original?
        uploaded_file.seek(0)
        file_name = (getattr(uploaded_file, "name", "") or "").lower()
        first_bytes = uploaded_file.read(16)
        uploaded_file.seek(0)

        is_enc_file = (
            file_name.endswith(".enc")
            or first_bytes.startswith(b"gAAAAA")
            or (len(first_bytes) > 0 and first_bytes[0] == 0x80)
        )

        if is_enc_file:
            # Archivo cifrado distribuido por el sistema: descifrar en memoria para obtener el hash unívoco
            try:
                enc_bytes = uploaded_file.read()
                uploaded_file.seek(0)
                decrypted_bytes = self.crypto_service.decrypt_bytes(enc_bytes)
                calculated_hash = hashlib.sha256(decrypted_bytes).hexdigest()
            except Exception:
                # Falla si el archivo está corrupto o fue cifrado con otra clave
                check_password(access_code, DUMMY_PBKDF2_HASH)
                return True, safe_generic_response
        else:
            # Archivo original (PDF, LibreOffice, MS Office): validación de cabeceras y estructura
            try:
                validate_document_file(uploaded_file)
            except ValidationError:
                check_password(access_code, DUMMY_PBKDF2_HASH)
                return True, safe_generic_response

            calculated_hash = calculate_file_sha256(uploaded_file)

        # 2. Búsqueda del documento en la base de datos
        document = EncryptedDocument.objects.filter(file_hash=calculated_hash).first()

        # Mitigación de Timing Attack si el documento no existe
        if not document:
            # Ejecuta trabajo computacional equivalente (PBKDF2) para simular la verificación
            check_password(access_code, DUMMY_PBKDF2_HASH)
            logger.warning(
                f"[FREEDEC SECURITY] Petición fallida: Documento con hash {calculated_hash} no existe."
            )
            return True, safe_generic_response

        # 3. Validación del access_code
        if not document.verify_access_code(access_code):
            logger.warning(
                f"[FREEDEC SECURITY] Petición fallida: Código de acceso incorrecto para hash {calculated_hash}."
            )
            return True, safe_generic_response

        # 4. Validación de lista blanca de correos autorizados
        if not document.is_email_authorized(normalized_email):
            logger.warning(
                f"[FREEDEC SECURITY] Petición fallida: Correo '{normalized_email}' no autorizado para {calculated_hash}."
            )
            return True, safe_generic_response

        # 5. Descifrado seguro de la contraseña interna
        try:
            plain_password = self.crypto_service.decrypt_string(document.encrypted_password)
        except Exception as exc:
            logger.error(
                f"[FREEDEC SECURITY CRITICAL] Fallo al descifrar contraseña interna de {calculated_hash}: {exc}"
            )
            return False, "Error interno en el procesamiento criptográfico."

        # 6. Envío exclusivo y automatizado de la clave mediante django.core.mail
        subject = "[Freedec] Clave de recuperación para su documento"
        message_body = (
            f"Estimado usuario,\n\n"
            f"Se ha verificado con éxito su documento y su autorización de acceso.\n\n"
            f"Su contraseña o clave de descifrado es:\n"
            f"--------------------------------------------------\n"
            f"{plain_password}\n"
            f"--------------------------------------------------\n\n"
            f"Por motivos de seguridad, no comparta esta clave con terceros.\n\n"
            f"Atentamente,\n"
            f"Sistema Automatizado Freedec"
        )
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@freedec.local")

        try:
            send_mail(
                subject=subject,
                message=message_body,
                from_email=from_email,
                recipient_list=[normalized_email],
                fail_silently=False,
            )
            logger.info(
                f"[FREEDEC AUDIT] Clave enviada exitosamente al correo autorizado '{normalized_email}' "
                f"para el hash {calculated_hash}."
            )
        except BadHeaderError as exc:
            logger.error(f"[FREEDEC SECURITY CRITICAL] Intento de inyección de cabeceras en correo: {exc}")
            return False, "Error de validación en los parámetros del mensaje de correo."
        except Exception as exc:
            logger.error(f"[FREEDEC ERROR] Fallo al enviar correo electrónico a '{normalized_email}': {exc}")
            return False, "Error al enviar el correo electrónico con las credenciales."

        return True, safe_generic_response

    def decrypt_document_with_password(
        self,
        encrypted_file_obj,
        password: str,
    ) -> Tuple[bool, Optional[bytes], Optional[str], Optional[str], str]:
        """
        Descifra un archivo .enc utilizando la contraseña suministrada por el usuario.
        
        Flujo de Seguridad:
        1. Lee los bytes cifrados del archivo .enc.
        2. Descifra el contenedor en memoria utilizando Fernet (con FREEDEC_FERNET_KEY).
        3. Calcula el hash SHA-256 de los bytes recuperados para encontrar el registro.
        4. Descifra la contraseña almacenada en la base de datos y la compara en tiempo constante
           con la contraseña introducida por el usuario (anti-Timing Attacks).
        5. Si la clave coincide, detecta la extensión y el mimetype original (PDF, Office, etc.)
           y entrega el archivo descifrado listo para su descarga.
        6. Si la clave no coincide o el archivo no existe, deniega la petición.
        
        Retorna:
            (éxito: bool, bytes_descifrados: Optional[bytes], nombre_archivo: Optional[str], mimetype: Optional[str], mensaje: str)
        """
        if not password or not password.strip():
            return False, None, None, None, "Debe proporcionar la contraseña de descifrado recibida por correo."

        if hasattr(encrypted_file_obj, "seek"):
            encrypted_file_obj.seek(0)

        enc_bytes = (
            encrypted_file_obj.read()
            if hasattr(encrypted_file_obj, "read")
            else bytes(encrypted_file_obj)
        )

        if not enc_bytes:
            return False, None, None, None, "El archivo cifrado está vacío."

        # 1. Descifrar con Fernet
        try:
            decrypted_bytes = self.crypto_service.decrypt_bytes(enc_bytes)
        except Exception:
            return False, None, None, None, "El archivo no es un archivo cifrado válido de Freedec o está dañado."

        # 2. Localizar registro por hash SHA-256
        calculated_hash = hashlib.sha256(decrypted_bytes).hexdigest()
        document = EncryptedDocument.objects.filter(file_hash=calculated_hash).first()

        if not document:
            return False, None, None, None, "No se encontró ningún registro correspondiente a este archivo."

        # 3. Descifrar contraseña almacenada y comparar en tiempo constante
        try:
            stored_password = self.crypto_service.decrypt_string(document.encrypted_password)
        except Exception as exc:
            logger.error(f"[FREEDEC SECURITY CRITICAL] Error al descifrar contraseña interna para hash {calculated_hash}: {exc}")
            return False, None, None, None, "Error interno en la verificación criptográfica."

        if not secrets.compare_digest(stored_password, password.strip()):
            logger.warning(f"[FREEDEC SECURITY] Contraseña incorrecta para el documento con hash {calculated_hash}.")
            return False, None, None, None, "La contraseña introducida no coincide con la clave del documento."

        # 4. Detección de extensión y tipo MIME
        ext, mimetype = detect_file_extension_and_mimetype(decrypted_bytes)
        suggested_filename = f"documento_{calculated_hash[:8]}{ext}"

        logger.info(f"[FREEDEC AUDIT] Documento con hash {calculated_hash} descifrado exitosamente con su contraseña.")
        return True, decrypted_bytes, suggested_filename, mimetype, "Documento descifrado correctamente."
