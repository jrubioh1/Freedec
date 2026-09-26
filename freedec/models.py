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
    encrypted_file_hash = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        db_index=True,
        verbose_name=_("Hash SHA-256 del archivo cifrado"),
        help_text=_("Hash SHA-256 hexadecimal del archivo .enc en reposo para búsqueda directa."),
    )
    admin_encrypted_dek = models.TextField(
        blank=True,
        null=True,
        verbose_name=_("DEK cifrada para Administrador"),
        help_text=_("Clave Maestra (DEK) cifrada con FREEDEC_FERNET_KEY para auditoría y descifrado preservado."),
    )
    user_envelopes = models.JSONField(
        default=dict,
        blank=True,
        verbose_name=_("Sobres digitales de usuario"),
        help_text=_("Sobres digitales de la Clave Maestra (DEK) indexados por email normalizado."),
    )
    allowed_emails = models.JSONField(
        default=list,
        verbose_name=_("Correos autorizados"),
        help_text=_("Lista de correos electrónicos autorizados en formato JSON (minúsculas)."),
    )
    is_consumed = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_("¿Archivo consumido?"),
        help_text=_("Indica si el documento ya ha sido descifrado y consumido por un destinatario final."),
    )
    consumed_by = models.EmailField(
        null=True,
        blank=True,
        verbose_name=_("Consumido por"),
        help_text=_("Correo del usuario final que consumió y provocó la destrucción del documento."),
    )
    consumed_at = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name=_("Fecha y hora de consumo"),
        help_text=_("Momento exacto en el que el documento fue consumido y su binario eliminado del disco."),
    )
    access_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("Veces accedido"),
        help_text=_("Número total de solicitudes de acceso o descifrados autorizados."),
    )
    last_accessed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Último acceso"),
        help_text=_("Fecha y hora de la última solicitud de acceso o descifrado."),
    )
    last_accessed_by = models.CharField(
        max_length=254,
        blank=True,
        null=True,
        verbose_name=_("Último correo que accedió"),
        help_text=_("Dirección de correo del último usuario que solicitó el acceso."),
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
        status_suffix = f" [CONSUMIDO por {self.consumed_by}]" if self.is_consumed else ""
        return f"{self.original_filename} (hash={self.file_hash[:8]}...){status_suffix}"

    def is_email_authorized(self, email: str) -> bool:
        """
        Comprueba si una dirección de correo está autorizada para recibir el acceso.
        Normaliza a minúsculas y elimina espacios para evitar evasiones de lista blanca.
        """
        if not email or not isinstance(self.allowed_emails, list):
            return False
        normalized_email = email.strip().lower()
        return normalized_email in [e.strip().lower() for e in self.allowed_emails if isinstance(e, str)]


class AccessVerificationToken(models.Model):
    """
    Token de verificación temporal y de un solo uso para acceso por correo (Magic Link / OTP).
    Prueba de posesión en tiempo real (Zero-Knowledge: solo se almacena el hash del token).
    """

    document = models.ForeignKey(
        EncryptedDocument,
        on_delete=models.CASCADE,
        related_name="tokens",
        verbose_name=_("Documento"),
    )
    email = models.EmailField(
        db_index=True,
        verbose_name=_("Correo del solicitante"),
    )
    token_hash = models.CharField(
        max_length=128,
        db_index=True,
        verbose_name=_("Hash del token"),
        help_text=_("Resumen PBKDF2/SHA-256 del token plano enviado por correo."),
    )
    otp_code = models.CharField(
        max_length=6,
        db_index=True,
        verbose_name=_("Código OTP"),
        help_text=_("Código numérico de 6 dígitos como alternativa al enlace directo."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de generación"),
    )
    expires_at = models.DateTimeField(
        verbose_name=_("Fecha de caducidad"),
        help_text=_("Caducidad estricta a 15 minutos."),
    )
    is_used = models.BooleanField(
        default=False,
        verbose_name=_("¿Utilizado?"),
        help_text=_("Indica si el token ya fue consumido para descargar el documento."),
    )

    class Meta:
        verbose_name = _("Token de Verificación de Acceso")
        verbose_name_plural = _("Tokens de Verificación de Acceso")
        ordering = ["-created_at"]

    def __str__(self):
        status = "USADO" if self.is_used else ("EXPIRADO" if self.is_expired() else "ACTIVO")
        return f"Token [{status}] {self.email} ({self.document.original_filename})"

    def is_expired(self) -> bool:
        from django.utils import timezone
        return timezone.now() >= self.expires_at

    def is_valid(self) -> bool:
        """Comprueba que el token no haya sido utilizado y esté dentro de la ventana de validez."""
        return (not self.is_used) and (not self.is_expired())


class DocumentAccessLog(models.Model):
    """
    Registro histórico de auditoría de accesos a un documento cifrado.
    Registra cada vez que un destinatario autorizado solicita acceso o descifra el archivo.
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
        default="solicitud_acceso",
        verbose_name=_("Acción"),
        help_text=_(
            "Tipo de evento: 'solicitud_acceso', 'descifrado_completado_burn', "
            "'intento_post_consumo', 'admin_inspeccion_preservada', 'intento_fallido'."
        ),
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name=_("Dirección IP"),
    )
    user_agent = models.TextField(
        null=True,
        blank=True,
        verbose_name=_("User-Agent"),
        help_text=_("Cadena de identificación del navegador/cliente para análisis forense."),
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
