import logging
import secrets
from django.contrib.auth.hashers import check_password
from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver

logger = logging.getLogger(__name__)


class EncryptedDocument(models.Model):
    """
    Modelo de almacenamiento seguro de documentos cifrados.
    
    Principios de ciberseguridad aplicados:
    1. Identificación por Hashing Criptográfico (file_hash):
       - Identifica unívocamente el documento mediante el resumen SHA-256 de su contenido original.
       - Elimina identificadores secuenciales o nombres predecibles, impidiendo ataques de enumeración (IDOR).
    2. Almacenamiento Cifrado (encrypted_file):
       - El archivo se almacena en el disco ya cifrado con AES-128-CBC + HMAC-SHA256 (Fernet).
       - Incluso con acceso físico o no autorizado al sistema de archivos, el contenido es inaccesible.
    3. Almacenamiento Zero-Knowledge del Código de Acceso (access_code):
       - Almacena el hash criptográfico robusto (PBKDF2/SHA-256) del access_code entregado al admin.
       - Si la base de datos se filtra, los códigos de acceso no pueden ser recuperados en claro.
    4. Cifrado de Contraseña en Reposo (encrypted_password):
       - La contraseña o clave interna de descifrado permanece siempre cifrada con la clave maestra Fernet.
    5. Lista Blanca de Destinatarios (allowed_emails):
       - Almacena las direcciones de correo autorizadas, siempre normalizadas en minúsculas.
    """

    file_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="Hash SHA-256 hexadecimal (64 caracteres) del archivo original sin cifrar.",
    )
    encrypted_file = models.FileField(
        upload_to="encrypted_docs/",
        help_text="Archivo binario cifrado en reposo con Fernet (AES-128-CBC + HMAC).",
    )
    access_code = models.CharField(
        max_length=128,
        help_text="Hash PBKDF2 del código secreto de acceso necesario para la verificación.",
    )
    encrypted_password = models.TextField(
        help_text="Contraseña o clave de descifrado cifrada con Fernet (token seguro).",
    )
    allowed_emails = models.JSONField(
        default=list,
        help_text="Lista de correos electrónicos autorizados en formato JSON (minúsculas).",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Fecha y hora de registro y cifrado del documento.",
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Fecha y hora de la última modificación del registro.",
    )

    class Meta:
        verbose_name = "Documento Cifrado"
        verbose_name_plural = "Documentos Cifrados"
        ordering = ["-created_at"]

    def __str__(self):
        return f"EncryptedDocument(hash={self.file_hash[:12]}..., created={self.created_at:%Y-%m-%d %H:%M})"

    def verify_access_code(self, raw_access_code: str) -> bool:
        """
        Verifica si el código en claro proporcionado coincide con el código almacenado.
        
        Soporta:
        - Códigos con hash criptográfico Django (PBKDF2/Argon2/BCrypt) vía `check_password`.
        - Códigos en texto plano históricos con comparación en tiempo constante (`secrets.compare_digest`)
          para mitigar vulnerabilidades de canal lateral (Timing Attacks).
        """
        if not raw_access_code:
            return False

        # Si el campo tiene formato de hash de Django (contiene '$')
        if "$" in self.access_code:
            return check_password(raw_access_code, self.access_code)

        # Fallback de seguridad en tiempo constante para texto plano
        return secrets.compare_digest(self.access_code, raw_access_code)

    def is_email_authorized(self, email: str) -> bool:
        """
        Comprueba si una dirección de correo está autorizada para recibir la clave.
        Normaliza a minúsculas y elimina espacios para evitar evasiones de lista blanca.
        """
        if not email or not isinstance(self.allowed_emails, list):
            return False
        normalized_email = email.strip().lower()
        return normalized_email in [e.strip().lower() for e in self.allowed_emails if isinstance(e, str)]


@receiver(post_delete, sender=EncryptedDocument)
def delete_physical_encrypted_file_on_delete(sender, instance, **kwargs):
    """
    Elimina automáticamente el archivo físico (.enc) del almacenamiento (disco / MEDIA_ROOT)
    cuando se elimina el registro en la base de datos.
    
    Aplica tanto a borrados individuales (doc.delete()) como a borrados masivos
    desde el panel de administración de Django o mediante QuerySet.delete().
    """
    if instance.encrypted_file:
        try:
            storage = instance.encrypted_file.storage
            name = instance.encrypted_file.name
            if name and storage.exists(name):
                storage.delete(name)
                logger.info(f"[FREEDEC AUDIT] Archivo físico eliminado del almacenamiento: {name}")
        except Exception as exc:
            logger.warning(
                f"[FREEDEC WARNING] No se pudo eliminar el archivo físico {instance.encrypted_file}: {exc}"
            )
