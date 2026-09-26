import os
from pathlib import Path
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent.parent

# Cargar variables de entorno desde archivo .env si existe (sin dependencias externas)
_env_path = BASE_DIR / ".env"
if _env_path.exists():
    with open(_env_path, "r", encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip().strip("'\""))

# Clave secreta estándar para Django Staging
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "django-insecure-staging-key-freedec-cybersec-demo-2026!#@$",
)

DEBUG = True

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Django REST Framework
    "rest_framework",
    # Freedec App
    "freedec.apps.FreedecConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# Base de datos ligera para Staging / Pruebas locales
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db_staging.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 6}},
]

LANGUAGE_CODE = "es-es"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# Almacenamiento multimedia para documentos cifrados
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media_staging"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ==============================================================================
# CONFIGURACIÓN DE FREEDEC Y CIBERSEGURIDAD
# ==============================================================================

# Clave maestra Fernet (32 bytes base64 url-safe).
# Si no está definida en entorno, generamos una fija y determinista para el sandbox local
# (en producción DEBE ser cargada vía variable de entorno estrictamente secreta).
FREEDEC_FERNET_KEY = os.environ.get(
    "FREEDEC_FERNET_KEY",
    "OE2bpfNsxK36xJUha369orE4qOZkCpEVYgMpjiUkNB8=",  # Clave de demostración de 32 bytes válidos
)
# Validamos y aseguramos que tenga 44 caracteres válidos base64
try:
    Fernet(FREEDEC_FERNET_KEY.encode("utf-8"))
except Exception:
    # Si la clave de fallback no fuera válida, genera una temporal para staging
    FREEDEC_FERNET_KEY = Fernet.generate_key().decode()

# Tamaño máximo de archivo permitido (50 MB)
FREEDEC_MAX_FILE_SIZE = 50 * 1024 * 1024

# ==============================================================================
# CONFIGURACIÓN DE CORREO ELECTRÓNICO (SMTP O CONSOLA)
# ==============================================================================
# Si EMAIL_HOST o EMAIL_BACKEND se definen en el entorno (.env), se usa el backend SMTP real.
# De lo contrario, en Staging se utiliza la consola para pruebas rápidas.
_has_smtp_host = bool(os.environ.get("EMAIL_HOST"))
_default_backend = (
    "django.core.mail.backends.smtp.EmailBackend"
    if _has_smtp_host
    else "django.core.mail.backends.console.EmailBackend"
)
EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND", _default_backend)
EMAIL_HOST = os.environ.get("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USE_TLS = os.environ.get("EMAIL_USE_TLS", "True").lower() in ("true", "1", "yes")
EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "False").lower() in ("true", "1", "yes")
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.environ.get(
    "DEFAULT_FROM_EMAIL",
    EMAIL_HOST_USER or "no-reply@freedec.local",
)
EMAIL_TIMEOUT = int(os.environ.get("EMAIL_TIMEOUT", 10))

# Configuración DRF para Staging
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/minute",  # Generoso en modo staging para facilitar tests
    },
}
