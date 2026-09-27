import logging
from typing import Any, List
from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)


class EncryptedDocument(models.Model):
    """
    Modelo de almacenamiento de documentos confidenciales cifrados.
    
    Criterios de seguridad y arquitectura:
    1. Cero transporte del binario por el cliente: El identificador unívoco
       y prueba de trámite es exclusivamente el hash SHA-256 del contenido original.
    2. Zero Human-Readable Passwords: No existen contraseñas humanas.
       El cifrado se realiza con una Clave Maestra de Datos (DEK) protegida a su vez
       con settings.FREEDEC_FERNET_KEY (Envelope Encryption).
    3. Burn-After-Read con opciones de política:
       - FIRST_ACCESS: Destrucción al primer acceso de cualquiera.
       - ALL_RECIPIENTS: Destrucción física cuando todos los autorizados hayan accedido.
    4. Reactivación y reapertura por hash idéntico conservando la trazabilidad.
    """

    class BurnPolicy(models.TextChoices):
        FIRST_ACCESS = "FIRST_ACCESS", _("Descarga única (primer acceso)")
        ALL_RECIPIENTS = "ALL_RECIPIENTS", _("Disponible para todos los destinatarios")

    original_filename = models.CharField(
        max_length=255,
        default="documento",
        verbose_name=_("Nombre original del documento"),
        help_text=_("Nombre del archivo original cargado en el sistema."),
    )
    description = models.TextField(
        default="Documento confidencial compartido a través de la pasarela segura Freedec.",
        blank=True,
        verbose_name=_("Descripción del documento"),
        help_text=_("Descripción informativa para las notificaciones por correo electrónico."),
    )
    file_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        verbose_name=_("Hash SHA-256"),
        help_text=_("Hash SHA-256 hexadecimal (64 caracteres) del archivo original."),
    )
    encrypted_file = models.FileField(
        upload_to="encrypted_docs/%Y/%m/",
        verbose_name=_("Archivo cifrado"),
        help_text=_("Archivo binario cifrado en reposo con la DEK."),
    )
    encrypted_dek = models.TextField(
        default="",
        verbose_name=_("Clave Maestra de Datos (DEK) cifrada"),
        help_text=_("DEK cifrada internamente con settings.FREEDEC_FERNET_KEY."),
    )
    allowed_emails = models.JSONField(
        default=list,
        verbose_name=_("Correos autorizados"),
        help_text=_("Lista de correos autorizados en minúsculas."),
    )
    burn_policy = models.CharField(
        max_length=20,
        choices=BurnPolicy.choices,
        default=BurnPolicy.FIRST_ACCESS,
        verbose_name=_("Política de destrucción"),
        help_text=_("Determina si se destruye al primer acceso o tras el acceso de todos."),
    )
    consumed_recipients = models.JSONField(
        default=list,
        blank=True,
        verbose_name=_("Destinatarios que han consumido"),
        help_text=_("Lista de correos que ya han descargado su copia individual."),
    )
    is_consumed = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name=_("¿Documento consumido?"),
        help_text=_("Indica si el documento ya fue canjeado y destruido del almacenamiento."),
    )
    consumed_by = models.CharField(
        max_length=254,
        null=True,
        blank=True,
        verbose_name=_("Consumido por"),
        help_text=_("Correo del usuario o resumen de destinatarios que retiraron el documento."),
    )
    consumed_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Fecha y hora del canje"),
        help_text=_("Momento exacto en el que el documento fue canjeado."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de alta"),
        help_text=_("Marca temporal de creación del registro."),
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name=_("Fecha de actualización"),
        help_text=_("Marca temporal de la última actualización."),
    )

    class Meta:
        verbose_name = _("Documento Cifrado")
        verbose_name_plural = _("Documentos Cifrados")
        ordering = ["-created_at"]
        permissions = [
            ("can_audit_download", _("Puede realizar descarga de auditoría administrativa")),
        ]

    def __str__(self) -> str:
        status_suffix = f" [CONSUMIDO por {self.consumed_by}]" if self.is_consumed else " [ACTIVO]"
        return f"{self.original_filename} (hash={self.file_hash[:8]}...){status_suffix}"

    def is_email_authorized(self, email: str) -> bool:
        """
        Comprueba si una dirección de correo está autorizada para acceder al documento.
        Normaliza a minúsculas y elimina espacios en blanco para evitar evasiones.
        """
        if not email or not isinstance(self.allowed_emails, list):
            return False
        normalized_email = email.strip().lower()
        return normalized_email in [
            e.strip().lower() for e in self.allowed_emails if isinstance(e, str)
        ]

    def is_email_consumed(self, email: str) -> bool:
        """Comprueba si un correo específico ya ha descargado su copia."""
        if not email or not isinstance(self.consumed_recipients, list):
            return False
        normalized_email = email.strip().lower()
        return normalized_email in [
            e.strip().lower() for e in self.consumed_recipients if isinstance(e, str)
        ]

    def are_all_recipients_consumed(self) -> bool:
        """Comprueba si todos los correos autorizados ya han descargado su copia."""
        if not isinstance(self.allowed_emails, list) or not self.allowed_emails:
            return True
        allowed_set = {e.strip().lower() for e in self.allowed_emails if isinstance(e, str) and e.strip()}
        consumed_set = {e.strip().lower() for e in self.consumed_recipients if isinstance(e, str) and e.strip()}
        return allowed_set.issubset(consumed_set)


class AccessVerificationToken(models.Model):
    """
    Token de verificación temporal y de un solo uso para verificación OTP en tiempo real.
    """

    document = models.ForeignKey(
        EncryptedDocument,
        on_delete=models.CASCADE,
        related_name="verification_tokens",
        verbose_name=_("Documento"),
    )
    email = models.EmailField(
        db_index=True,
        verbose_name=_("Correo oficial del solicitante"),
    )
    otp_code = models.CharField(
        max_length=6,
        verbose_name=_("Código OTP"),
        help_text=_("Código numérico de 6 dígitos generado criptográficamente."),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Fecha de creación"),
    )
    expires_at = models.DateTimeField(
        verbose_name=_("Fecha de caducidad"),
        help_text=_("Caducidad estricta a 15 minutos."),
    )
    is_used = models.BooleanField(
        default=False,
        verbose_name=_("¿Utilizado?"),
        help_text=_("Indica si el token ya fue consumido o revocado."),
    )
    failed_attempts = models.PositiveSmallIntegerField(
        default=0,
        verbose_name=_("Intentos fallidos"),
        help_text=_("Contador de intentos fallidos. Se revoca al alcanzar 3."),
    )

    class Meta:
        verbose_name = _("Token de Verificación OTP")
        verbose_name_plural = _("Tokens de Verificación OTP")
        ordering = ["-created_at"]

    def __str__(self) -> str:
        status = "USADO" if self.is_used else ("ACTIVO" if self.is_valid() else "EXPIRADO/BLOQUEADO")
        return f"Token [{status}] {self.email} ({self.document.original_filename})"

    def is_valid(self) -> bool:
        """
        Retorna True si no ha sido usado, no ha caducado y no supera los 3 intentos fallidos.
        """
        return (not self.is_used) and (timezone.now() <= self.expires_at) and (self.failed_attempts < 3)

    def register_failed_attempt(self) -> None:
        """
        Incrementa failed_attempts en 1. Si alcanza 3, marca is_used = True
        para revocar el token permanentemente.
        """
        self.failed_attempts += 1
        if self.failed_attempts >= 3:
            self.is_used = True
        self.save(update_fields=["failed_attempts", "is_used"])


class DocumentAccessLog(models.Model):
    """
    Registro histórico de auditoría legal de accesos y ciclo de vida del documento.
    """

    class Action(models.TextChoices):
        SOLICITUD_OTP = "solicitud_otp", _("Solicitud de código de verificación")
        OTP_ENVIADO = "otp_enviado", _("Código de verificación enviado")
        DESCIFRADO_EXITOSO_BURN = "descifrado_exitoso_burn", _("Descarga completada y retirada de la pasarela")
        DESCIFRADO_PARCIAL_PRESERVADO = "descifrado_parcial_preservado", _("Descarga individual completada (en espera de restantes destinatarios)")
        REACTIVACION_DOCUMENTO = "reactivacion_documento", _("Reactivación de documento")
        INTENTO_POST_CONSUMO = "intento_post_consumo", _("Acceso a documento no disponible")
        OTP_INVALIDO_BLOQUEADO = "otp_invalido_bloqueado", _("Código bloqueado por intentos fallidos")
        ADMIN_DESCARGA_PRESERVADA = "admin_descarga_preservada", _("Descarga de auditoría administrativa")

    document = models.ForeignKey(
        EncryptedDocument,
        on_delete=models.CASCADE,
        related_name="access_logs",
        verbose_name=_("Documento"),
    )
    email = models.CharField(
        max_length=254,
        verbose_name=_("Correo del solicitante"),
    )
    action = models.CharField(
        max_length=50,
        choices=Action.choices,
        verbose_name=_("Acción"),
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
    )
    created_at = models.DateTimeField(
        default=timezone.now,
        verbose_name=_("Fecha y hora"),
    )

    class Meta:
        verbose_name = _("Registro de Auditoría de Acceso")
        verbose_name_plural = _("Registros de Auditoría de Accesos")
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"[{self.created_at:%Y-%m-%d %H:%M:%S}] {self.email} -> {self.action} ({self.document.original_filename})"


@receiver(post_delete, sender=EncryptedDocument)
def auto_delete_physical_file_on_delete(sender: Any, instance: EncryptedDocument, **kwargs: Any) -> None:
    """
    Elimina físicamente el archivo del disco con borrado seguro cuando
    se elimina el registro del documento de la base de datos.
    """
    if instance.encrypted_file:
        try:
            from freedec.services import shred_and_delete_file
            shred_and_delete_file(instance.encrypted_file)
        except Exception as exc:
            logger.warning(f"[FREEDEC] No se pudo ejecutar borrado seguro de {instance.encrypted_file}: {exc}")
