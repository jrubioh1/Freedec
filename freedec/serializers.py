import json
from django.conf import settings
from rest_framework import serializers

from freedec.validators import validate_document_file, validate_safe_email

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024


class AdminDocumentUploadSerializer(serializers.Serializer):
    """
    Serializador para la subida inicial, cifrado y registro del documento por parte del administrador.
    
    Campos de entrada:
    - original_file: Archivo binario (PDF, LibreOffice o Microsoft Office).
    - plain_password: Clave de descifrado en texto plano que será cifrada antes de almacenarse.
    - allowed_emails: Lista de correos autorizados a recibir la contraseña.
    """

    original_file = serializers.FileField(
        required=True,
        help_text="Archivo original en formato PDF, LibreOffice o Microsoft Office.",
    )
    plain_password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=8,
        trim_whitespace=False,
        help_text="Contraseña en texto plano para cifrar y almacenar de forma segura (mínimo 8 caracteres).",
    )
    allowed_emails = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=False,
        required=True,
        help_text="Lista de correos autorizados a solicitar la clave de recuperación.",
    )

    def to_internal_value(self, data):
        """
        Soporte robusto para Multipart Form-Data:
        Si 'allowed_emails' se envía como cadena JSON o valores separados por coma,
        se deserializa limpiamente a una lista de Python antes de la validación estándar.
        """
        mutable_data = data.copy() if hasattr(data, "copy") else dict(data)
        raw_emails = mutable_data.get("allowed_emails")

        if isinstance(raw_emails, str):
            try:
                parsed = json.loads(raw_emails)
                if isinstance(parsed, list):
                    mutable_data["allowed_emails"] = parsed
                else:
                    mutable_data["allowed_emails"] = [raw_emails]
            except (json.JSONDecodeError, ValueError):
                # Soporte para lista separada por comas
                mutable_data["allowed_emails"] = [
                    e.strip() for e in raw_emails.split(",") if e.strip()
                ]

        return super().to_internal_value(mutable_data)

    def validate_original_file(self, value):
        """
        Valida que el archivo no esté vacío, respete el límite de tamaño
        y corresponda a un formato permitido (PDF, LibreOffice, MS Office)
        mediante inspección de Magic Bytes y estructura interna.
        """
        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if value.size <= 0:
            raise serializers.ValidationError("El archivo no puede estar vacío.")
        if value.size > max_size:
            raise serializers.ValidationError(
                f"El archivo excede el tamaño máximo permitido de {max_size // (1024 * 1024)} MB."
            )

        # Validación criptográfica y estructural de formato (OWASP A03 / A08)
        try:
            return validate_document_file(value)
        except Exception as exc:
            raise serializers.ValidationError(str(exc))

    def validate_allowed_emails(self, value):
        """
        Valida, desinfecta contra CRLF y normaliza en minúsculas todas las
        direcciones de correo electrónico autorizadas.
        """
        if not value:
            raise serializers.ValidationError("Debe especificar al menos un correo autorizado.")

        normalized_emails = set()
        for raw_email in value:
            try:
                clean_email = validate_safe_email(raw_email)
                normalized_emails.add(clean_email)
            except Exception as exc:
                raise serializers.ValidationError(f"Correo inválido '{raw_email}': {exc}")

        return sorted(list(normalized_emails))


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
