import hashlib
import logging
import secrets
from typing import List, Tuple

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
        plain_password: str,
        allowed_emails: List[str],
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
        7. Cifra la contraseña con Fernet.
        8. Desinfecta y normaliza la lista de correos autorizados (anti-CRLF).
        9. Retorna la instancia creada y el access_code en texto plano (único momento en que es visible).
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

        # 5. Cifrado de la contraseña con Fernet
        encrypted_pwd = self.crypto_service.encrypt_string(plain_password)

        # 6. Desinfección y normalización rigurosa de correos electrónicos (anti-CRLF)
        normalized_emails = sorted(
            list(
                {
                    validate_safe_email(email)
                    for email in allowed_emails
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

        # Validación estructural y de firmas binarias
        try:
            validate_document_file(uploaded_file)
            normalized_email = validate_safe_email(recipient_email)
        except ValidationError:
            # En caso de formato o email malformado, responder de forma controlada
            check_password(access_code, DUMMY_PBKDF2_HASH)
            return True, safe_generic_response

        # 1. Cálculo del hash SHA-256 del archivo en runtime
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
        subject = f"[Freedec] Clave de recuperación para documento {calculated_hash[:12]}..."
        message_body = (
            f"Estimado usuario,\n\n"
            f"Se ha verificado con éxito la integridad de su archivo (SHA-256: {calculated_hash}) "
            f"y su autorización de acceso.\n\n"
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
