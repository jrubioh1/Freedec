from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from freedec.validators import validate_document_file, validate_safe_email

DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024


class PublicAccessRequestForm(forms.Form):
    """
    Formulario web para la solicitud pública de acceso mediante Enlace Mágico / OTP.
    El usuario final sube el archivo cifrado (.enc) y proporciona su correo electrónico.
    """

    file = forms.FileField(
        label=_("Archivo Cifrado (.enc)"),
        help_text=_("Seleccione el archivo cifrado (.enc) que desea abrir."),
        widget=forms.FileInput(attrs={"class": "form-file-input", "id": "public_file"}),
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
        help_text=_("Dirección autorizada a la que se enviará el enlace de acceso directo y código OTP."),
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

    def clean_email(self):
        raw_email = self.cleaned_data.get("email", "")
        return validate_safe_email(raw_email)


class PublicConsumeDocumentForm(forms.Form):
    """
    Formulario para descifrar y consumir el documento mediante token URL o código OTP de 6 dígitos.
    """

    token = forms.CharField(
        required=False,
        widget=forms.HiddenInput(attrs={"id": "consume_token"}),
    )
    otp_code = forms.CharField(
        label=_("Código OTP (6 dígitos)"),
        required=False,
        max_length=6,
        widget=forms.TextInput(
            attrs={
                "class": "form-control font-mono text-center",
                "placeholder": "123456",
                "id": "otp_code",
                "maxlength": "6",
                "autocomplete": "one-time-code",
            }
        ),
        help_text=_("Introduzca el código OTP de 6 dígitos recibido por correo."),
    )
    email = forms.CharField(
        label=_("Correo Electrónico"),
        required=False,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": _("su-correo@ejemplo.com"),
                "id": "consume_email",
            }
        ),
        help_text=_("Requerido únicamente si utiliza código OTP manual."),
    )

    def clean(self):
        cleaned_data = super().clean()
        token = cleaned_data.get("token")
        otp_code = cleaned_data.get("otp_code")

        if not token and not otp_code:
            raise ValidationError(_("Debe proporcionar el token de acceso o el código OTP."))

        if otp_code and not token:
            email = cleaned_data.get("email")
            if not email:
                raise ValidationError(_("Debe indicar su correo electrónico para validar el código OTP."))
            cleaned_data["email"] = validate_safe_email(email)

        return cleaned_data


# Alias de compatibilidad
PublicPasswordRequestForm = PublicAccessRequestForm
PublicDecryptDocumentForm = PublicConsumeDocumentForm
