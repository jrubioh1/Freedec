from django.conf import settings
from rest_framework import serializers

from freedec.validators import validate_document_file, validate_safe_email

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024



class PublicPasswordRequestSerializer(serializers.Serializer):
    """
    Serializador para la validación de peticiones públicas de recuperación de contraseña.
    
    Campos de entrada:
    - file: El archivo que el usuario final sube para que el servidor compute su SHA-256 en runtime.
    - access_code: Código secreto proporcionado por el administrador.
    - email: Correo electrónico del solicitante que debe coincidir con la lista de autorizados.
    """

    file = serializers.FileField(
        required=True,
        help_text="Archivo original para calcular su hash SHA-256 en tiempo de ejecución.",
    )
    access_code = serializers.CharField(
        write_only=True,
        required=True,
        trim_whitespace=True,
        help_text="Código secreto de acceso distribuido por el administrador.",
    )
    email = serializers.CharField(
        required=True,
        help_text="Correo electrónico registrado del solicitante.",
    )

    def validate_file(self, value):
        """Valida tamaño, firma binaria y estructura del archivo cargado para evitar abusos DoS."""
        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if value.size <= 0:
            raise serializers.ValidationError("El archivo proporcionado no contiene datos.")
        if value.size > max_size:
            raise serializers.ValidationError(
                f"El archivo supera el tamaño máximo permitido de {max_size // (1024 * 1024)} MB."
            )

        name_lower = (value.name or "").lower()
        if name_lower.endswith(".enc"):
            return value

        # Validación estructural de formato (OWASP A03 / A08)
        try:
            return validate_document_file(value)
        except Exception as exc:
            raise serializers.ValidationError(str(exc))

    def validate_email(self, value):
        """Valida contra inyecciones CRLF y normaliza el correo en minúsculas."""
        try:
            return validate_safe_email(value)
        except Exception as exc:
            raise serializers.ValidationError(str(exc))
