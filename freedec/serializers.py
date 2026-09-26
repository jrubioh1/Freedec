from django.conf import settings
from rest_framework import serializers

from freedec.validators import validate_document_file, validate_safe_email

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024



class PublicAccessRequestSerializer(serializers.Serializer):
    """
    Serializador para la solicitud de acceso mediante Enlace Mágico y OTP (Prueba de posesión).
    """

    file = serializers.FileField(
        required=True,
        help_text="Archivo cifrado (.enc) o documento de control.",
    )
    email = serializers.CharField(
        required=True,
        help_text="Correo electrónico registrado del solicitante.",
    )
    access_code = serializers.CharField(
        write_only=True,
        required=False,
        default="",
        trim_whitespace=True,
        help_text="Opcional (para compatibilidad con clientes existentes).",
    )

    def validate_file(self, value):
        """Valida tamaño y firma binaria del archivo cargado."""
        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if value.size <= 0:
            raise serializers.ValidationError("El archivo proporcionado no contiene datos.")
        if value.size > max_size:
            max_mb = max_size // (1024 * 1024)
            raise serializers.ValidationError(
                f"El archivo supera el tamaño máximo permitido de {max_mb} MB."
            )

        name_lower = (value.name or "").lower()
        if name_lower.endswith(".enc"):
            return value

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


class PublicConsumeSerializer(serializers.Serializer):
    """
    Serializador para validar el token de enlace mágico o el código OTP.
    """

    token = serializers.CharField(required=False, allow_blank=True, default="")
    otp_code = serializers.CharField(required=False, allow_blank=True, default="", max_length=6)
    email = serializers.CharField(required=False, allow_blank=True, default="")

    def validate(self, attrs):
        token = attrs.get("token", "").strip()
        otp = attrs.get("otp_code", "").strip()
        if not token and not otp:
            raise serializers.ValidationError("Debe proporcionar un token de acceso o código OTP.")
        if otp and not token and not attrs.get("email"):
            raise serializers.ValidationError("Debe indicar su correo electrónico para validar el código OTP.")
        return attrs


# Alias de compatibilidad
PublicPasswordRequestSerializer = PublicAccessRequestSerializer
