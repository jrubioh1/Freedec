import base64
import logging
from cryptography.fernet import Fernet
from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)


class FreedecConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "freedec"
    verbose_name = "Freedec - Sistema de Entrega y Canje Seguro de Documentos"

    def ready(self) -> None:
        """
        Validación obligatoria en el arranque de la aplicación.
        Garantiza que settings.FREEDEC_FERNET_KEY esté configurada en el entorno y sea
        una clave válida de Fernet (32 bytes codificados en base64 url-safe).
        Si no es válida o falta, lanza ImproperlyConfigured para impedir que Django inicie inseguro.
        """
        fernet_key = getattr(settings, "FREEDEC_FERNET_KEY", None)

        if not fernet_key:
            raise ImproperlyConfigured(
                "[FREEDEC SECURITY CRITICAL] Falta la configuración obligatoria 'FREEDEC_FERNET_KEY' en settings.py. "
                "Debe ser una clave simétrica de 32 bytes codificada en base64 url-safe generada con Fernet.generate_key()."
            )

        try:
            if isinstance(fernet_key, str):
                raw_bytes = fernet_key.strip().encode("utf-8")
            elif isinstance(fernet_key, bytes):
                raw_bytes = fernet_key.strip()
            else:
                raise ValueError("El tipo de FREEDEC_FERNET_KEY debe ser str o bytes.")

            decoded = base64.urlsafe_b64decode(raw_bytes)
            if len(decoded) != 32:
                raise ImproperlyConfigured(
                    f"[FREEDEC SECURITY CRITICAL] 'FREEDEC_FERNET_KEY' debe decodificarse exactamente en "
                    f"32 bytes criptográficos (se obtuvieron {len(decoded)} bytes)."
                )

            # Instanciación estricta de Fernet para validar formato y paridad
            Fernet(raw_bytes)
        except ImproperlyConfigured:
            raise
        except Exception as exc:
            raise ImproperlyConfigured(
                f"[FREEDEC SECURITY CRITICAL] 'FREEDEC_FERNET_KEY' no es una clave válida de Fernet: {exc}"
            ) from exc
