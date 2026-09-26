import os
from pathlib import Path
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent.parent

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
    "cGFzc3dvcmRfZXhhbXBsZV8zMl9ieXRlc19mb3Jfc3RhZ2luZw==",  # Clave de demostración
)
# Validamos y aseguramos que tenga 44 caracteres válidos base64
try:
    Fernet(FREEDEC_FERNET_KEY.encode("utf-8"))
except Exception:
    # Si la clave de fallback no fuera válida, genera una temporal para staging
    FREEDEC_FERNET_KEY = Fernet.generate_key().decode()

# Tamaño máximo de archivo permitido (50 MB)
FREEDEC_MAX_FILE_SIZE = 50 * 1024 * 1024

# En modo Staging, las contraseñas enviadas por email se imprimen en consola (Terminal)
# facilitando la prueba inmediata sin requerir configuración SMTP.
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = "freedec-security@local-stage.internal"

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
