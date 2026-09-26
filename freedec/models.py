import logging
import secrets
from django.contrib.auth.hashers import check_password
from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils.translation import gettext_lazy as _

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

    original_filename = models.CharField(
        max_length=255,
        default="documento",
        verbose_name=_("Nombre original del archivo"),
        help_text=_("Nombre del archivo original subido por el administrador."),
    )
    file_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        verbose_name=_("Hash SHA-256"),
        help_text=_("Hash SHA-256 hexadecimal (64 caracteres) del archivo original sin cifrar."),
    )
    encrypted_file = models.FileField(
        upload_to="encrypted_docs/",
        verbose_name=_("Archivo cifrado"),
        help_text=_("Archivo binario cifrado en reposo con Fernet (AES-128-CBC + HMAC)."),
    )
    access_code = models.CharField(
        max_length=128,
        verbose_name=_("Código de acceso"),
        help_text=_("Hash PBKDF2 del código secreto de acceso necesario para la verificación."),
    )
    encrypted_password = models.TextField(
        verbose_name=_("Contraseña cifrada"),
        help_text=_("Contraseña o clave de descifrado cifrada con Fernet (token seguro)."),
    )
    allowed_emails = models.JSONField(
        default=list,
        verbose_name=_("Correos autorizados"),
        help_text=_("Lista de correos electrónicos autorizados en formato JSON (minúsculas)."),
    )
    access_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("Veces accedido"),
        help_text=_("Número total de solicitudes de contraseña o descifrados autorizados."),
    )
    last_accessed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Último acceso"),
        help_text=_("Fecha y hora de la última solicitud de contraseña o descifrado."),
    )
    last_accessed_by = models.CharField(
        max_length=254,
        blank=True,
        null=True,
        verbose_name=_("Último correo que accedió"),
        help_text=_("Dirección de correo del último usuario que solicitó la clave."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de creación"),
        help_text=_("Fecha y hora de registro y cifrado del documento."),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Fecha de actualización"),
        help_text=_("Fecha y hora de la última modificación del registro."),
    )

    class Meta:
        verbose_name = _("Documento Cifrado")
        verbose_name_plural = _("Documentos Cifrados")
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.original_filename} (hash={self.file_hash[:8]}...)"

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


class DocumentAccessLog(models.Model):
    """
    Registro histórico de auditoría de accesos a un documento cifrado.
    Registra cada vez que un destinatario autorizado solicita la contraseña o descifra el archivo.
    """

    document = models.ForeignKey(
        EncryptedDocument,
        on_delete=models.CASCADE,
        related_name="access_logs",
        verbose_name=_("Documento"),
    )
    email = models.CharField(
        max_length=254,
        verbose_name=_("Correo solicitante"),
    )
    action = models.CharField(
        max_length=50,
        default="solicitud_clave",
        verbose_name=_("Acción"),
        help_text=_("Tipo de evento: 'solicitud_clave' o 'descifrado'."),
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_("Dirección IP"),
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha y hora de acceso"),
    )

    class Meta:
        verbose_name = _("Registro de Auditoría de Acceso")
        verbose_name_plural = _("Registros de Auditoría de Accesos")
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] {self.email} -> {self.action} ({self.document.original_filename})"


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
