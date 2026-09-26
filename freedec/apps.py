import base64
import logging
from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)


class FreedecConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "freedec"
    verbose_name = "Freedec - Cifrado y Recuperación Segura"

    def ready(self):
        """
        Hook de verificación de seguridad en el arranque de la aplicación.
        Garantiza que la clave maestra Fernet (FREEDEC_FERNET_KEY) esté definida y cumpla
        con los requisitos criptográficos (32 bytes codificados en base64 url-safe).
        """
        fernet_key = getattr(settings, "FREEDEC_FERNET_KEY", None)

        if not fernet_key:
            # En entornos de testing o desarrollo inicial, permitir fallback con advertencia
            if getattr(settings, "TESTING", False):
                logger.warning(
                    "[FREEDEC SECURITY WARNING] No se detectó 'FREEDEC_FERNET_KEY'. "
                    "Se generará una clave efímera para pruebas."
                )
                return
            raise ImproperlyConfigured(
                "[FREEDEC SECURITY CRITICAL] Falta la configuración 'FREEDEC_FERNET_KEY' en settings.py. "
                "Debe ser una cadena base64 url-safe de 32 bytes generada con cryptography.fernet.Fernet.generate_key()."
            )

        # Validación estructural de la clave
        try:
            raw_key = base64.urlsafe_b64decode(fernet_key)
            if len(raw_key) != 32:
                raise ImproperlyConfigured(
                    f"[FREEDEC SECURITY CRITICAL] 'FREEDEC_FERNET_KEY' debe decodificarse en exactamente "
                    f"32 bytes criptográficos (se obtuvieron {len(raw_key)} bytes)."
                )
        except Exception as exc:
            raise ImproperlyConfigured(
                f"[FREEDEC SECURITY CRITICAL] 'FREEDEC_FERNET_KEY' no es una clave válida Fernet/Base64: {exc}"
            ) from exc
