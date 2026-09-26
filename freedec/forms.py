from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from freedec.validators import (
    normalize_and_validate_email_list,
    validate_document_file,
    validate_safe_email,
)

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024


class AdminDocumentUploadForm(forms.Form):
    """
    Formulario web para la interfaz gráfica administrativa.
    Permite subir el archivo original, definir la clave y los correos autorizados.
    """

    original_file = forms.FileField(
        label=_("Archivo Documental"),
        help_text=_(
            "Formatos admitidos: PDF, LibreOffice (.odt, .ods, .odp, .odg) o Microsoft Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt)."
        ),
        widget=forms.FileInput(attrs={"class": "form-file-input", "id": "original_file"}),
    )
    plain_password = forms.CharField(
        label=_("Contraseña de Descifrado"),
        min_length=8,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": _("Mínimo 8 caracteres de alta entropía..."),
                "id": "plain_password",
            }
        ),
        help_text=_("Clave que será cifrada internamente con Fernet (AES-128-CBC + HMAC)."),
    )
    allowed_emails = forms.CharField(
        label=_("Correos Electrónicos Autorizados"),
        required=False,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": _("destinatario@empresa.com"),
                "id": "allowed_emails",
            }
        ),
        help_text=_(
            "Direcciones de correo autorizadas a recibir la contraseña. Use el botón '+' para agregar más destinatarios."
        ),
    )

    def clean_original_file(self):
        file_obj = self.cleaned_data.get("original_file")
        if not file_obj:
            raise ValidationError(_("Debe seleccionar un archivo."))

        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if file_obj.size > max_size:
            max_mb = max_size // (1024 * 1024)
            raise ValidationError(
                _("El archivo excede el tamaño máximo permitido de %(max_size)s MB.")
                % {"max_size": max_mb}
            )

        # Validación estructural y de firmas binarias (Magic Bytes & Anti-Zip Bomb)
        return validate_document_file(file_obj)

    def clean_allowed_emails(self):
        # Admite múltiples campos input ('allowed_emails'), delimitadores o listas
        if hasattr(self.data, "getlist"):
            raw_entries = self.data.getlist("allowed_emails")
        else:
            raw_val = self.cleaned_data.get("allowed_emails") or self.data.get("allowed_emails") or ""
            raw_entries = [raw_val] if isinstance(raw_val, str) else list(raw_val)

        return normalize_and_validate_email_list(raw_entries)


class PublicPasswordRequestForm(forms.Form):
    """
    Formulario web para la interfaz gráfica pública.
    El usuario final sube su copia del archivo, el access_code y su correo electrónico.
    """

    file = forms.FileField(
        label=_("Documento"),
        help_text=_("Seleccione el archivo que desea consultar."),
        widget=forms.FileInput(attrs={"class": "form-file-input", "id": "public_file"}),
    )
    access_code = forms.CharField(
        label=_("Código de Acceso"),
        widget=forms.TextInput(
            attrs={
                "class": "form-control font-mono",
                "placeholder": _("Introduzca su código de acceso..."),
                "id": "access_code",
                "autocomplete": "off",
            }
        ),
        help_text=_("Código facilitado por el emisor del documento."),
    )
    email = forms.CharField(
        label=_("Correo Electrónico"),
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": _("su-correo@ejemplo.com"),
                "id": "email",
            }
        ),
        help_text=_("Dirección de correo donde se enviará la contraseña."),
    )

    def clean_file(self):
        file_obj = self.cleaned_data.get("file")
        if not file_obj:
            raise ValidationError(_("Debe proporcionar un archivo."))

        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if file_obj.size > max_size:
            max_mb = max_size // (1024 * 1024)
            raise ValidationError(
                _("El archivo excede el tamaño máximo permitido de %(max_size)s MB.")
                % {"max_size": max_mb}
            )

        name_lower = (file_obj.name or "").lower()
        if name_lower.endswith(".enc"):
            return file_obj

        return validate_document_file(file_obj)

    def clean_email(self):
        raw_email = self.cleaned_data.get("email", "")
        return validate_safe_email(raw_email)


class PublicDecryptDocumentForm(forms.Form):
    """
    Formulario público para descifrar un archivo .enc proporcionando la contraseña
    recibida por correo electrónico.
    """

    file = forms.FileField(
        label=_("Archivo Cifrado (.enc)"),
        help_text=_("Seleccione el archivo con extensión .enc que desea descifrar."),
        widget=forms.FileInput(attrs={"class": "form-file-input", "id": "enc_file"}),
    )
    password = forms.CharField(
        label=_("Contraseña de Descifrado"),
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control font-mono",
                "placeholder": _("Pegue la contraseña recibida por correo..."),
                "id": "decrypt_password",
                "autocomplete": "off",
            }
        ),
        help_text=_("Contraseña que le fue remitida a su correo electrónico tras la verificación."),
    )

    def clean_file(self):
        file_obj = self.cleaned_data.get("file")
        if not file_obj:
            raise ValidationError(_("Debe proporcionar un archivo."))

        max_size = getattr(settings, "FREEDEC_MAX_FILE_SIZE", DEFAULT_MAX_FILE_SIZE)
        if file_obj.size > max_size:
            max_mb = max_size // (1024 * 1024)
            raise ValidationError(
                _("El archivo excede el tamaño máximo permitido de %(max_size)s MB.")
                % {"max_size": max_mb}
            )
        return file_obj

    def clean_password(self):
        pwd = self.cleaned_data.get("password", "")
        if not pwd or not pwd.strip():
            raise ValidationError(_("Debe introducir la contraseña de descifrado."))
        return pwd.strip()
