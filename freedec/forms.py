from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError

from freedec.validators import validate_document_file, validate_safe_email

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024


class AdminDocumentUploadForm(forms.Form):
    """
    Formulario web para la interfaz gráfica administrativa.
    Permite subir el archivo original, definir la clave y los correos autorizados.
    """

    original_file = forms.FileField(
        label="Archivo Documental",
        help_text="Formatos admitidos: PDF, LibreOffice (.odt, .ods, .odp, .odg) o Microsoft Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt).",
        widget=forms.FileInput(attrs={"class": "form-file-input", "id": "original_file"}),
    )
    plain_password = forms.CharField(
        label="Contraseña de Descifrado",
        min_length=8,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Mínimo 8 caracteres de alta entropía...",
                "id": "plain_password",
            }
        ),
        help_text="Clave que será cifrada internamente con Fernet (AES-128-CBC + HMAC).",
    )
    allowed_emails = forms.CharField(
        label="Correos Electrónicos Autorizados",
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "rows": 3,
                "placeholder": "ejemplo1@empresa.com, ejemplo2@empresa.com (separados por coma o salto de línea)",
                "id": "allowed_emails",
            }
        ),
        help_text="Solo los correos especificados podrán solicitar y recibir la contraseña descifrada.",
    )

    def clean_original_file(self):
        file_obj = self.cleaned_data.get("original_file")
        if not file_obj:
            raise ValidationError("Debe seleccionar un archivo.")

        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if file_obj.size > max_size:
            raise ValidationError(
                f"El archivo excede el tamaño máximo permitido de {max_size // (1024 * 1024)} MB."
            )

        # Validación estructural y de firmas binarias (Magic Bytes & Anti-Zip Bomb)
        return validate_document_file(file_obj)

    def clean_allowed_emails(self):
        raw_text = self.cleaned_data.get("allowed_emails", "")
        # Separar por comas, puntos y comas o saltos de línea
        lines = raw_text.replace(";", ",").replace("\n", ",").split(",")
        cleaned_list = []

        for item in lines:
            trimmed = item.strip()
            if trimmed:
                try:
                    clean_email = validate_safe_email(trimmed)
                    cleaned_list.append(clean_email)
                except ValidationError as exc:
                    raise ValidationError(f"Correo inválido '{trimmed}': {exc.message}")

        if not cleaned_list:
            raise ValidationError("Debe indicar al menos una dirección de correo válida.")

        return sorted(list(set(cleaned_list)))


class PublicPasswordRequestForm(forms.Form):
    """
    Formulario web para la interfaz gráfica pública.
    El usuario final sube su copia del archivo, el access_code y su correo electrónico.
    """

    file = forms.FileField(
        label="Archivo para Verificación de Integridad",
        help_text="Suba el documento en su poder para calcular su hash SHA-256 en runtime.",
        widget=forms.FileInput(attrs={"class": "form-file-input", "id": "public_file"}),
    )
    access_code = forms.CharField(
        label="Código Secreto de Acceso",
        widget=forms.TextInput(
            attrs={
                "class": "form-control font-mono",
                "placeholder": "Pegue el código de acceso entregado por el administrador...",
                "id": "access_code",
                "autocomplete": "off",
            }
        ),
        help_text="Código aleatorio de 256 bits entregado por el administrador.",
    )
    email = forms.CharField(
        label="Su Correo Electrónico Registrado",
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "correo@ejemplo.com",
                "id": "email",
            }
        ),
        help_text="Si está autorizado, recibirá la contraseña descifrada en su bandeja de entrada.",
    )

    def clean_file(self):
        file_obj = self.cleaned_data.get("file")
        if not file_obj:
            raise ValidationError("Debe proporcionar un archivo.")

        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if file_obj.size > max_size:
            raise ValidationError(
                f"El archivo excede el tamaño máximo permitido de {max_size // (1024 * 1024)} MB."
            )

        return validate_document_file(file_obj)

    def clean_email(self):
        raw_email = self.cleaned_data.get("email", "")
        return validate_safe_email(raw_email)
