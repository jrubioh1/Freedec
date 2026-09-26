from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import activate, check_for_language, gettext as _
from django.views import View


def set_language_view(request):
    """
    Cambia el idioma activo de la interfaz (es/en) y redirige a la página anterior.
    Almacena la preferencia tanto en la sesión como en la cookie de idioma de Django.
    """
    lang_code = request.GET.get("lang") or request.POST.get("language")
    next_url = (
        request.GET.get("next")
        or request.META.get("HTTP_REFERER")
        or reverse("freedec:gui-public-request")
    )
    response = HttpResponseRedirect(next_url)
    if lang_code and check_for_language(lang_code):
        if hasattr(request, "session"):
            request.session["django_language"] = lang_code
        response.set_cookie(
            getattr(settings, "LANGUAGE_COOKIE_NAME", "django_language"),
            lang_code,
            max_age=getattr(settings, "LANGUAGE_COOKIE_AGE", 365 * 24 * 60 * 60),
            path=getattr(settings, "LANGUAGE_COOKIE_PATH", "/"),
            domain=getattr(settings, "LANGUAGE_COOKIE_DOMAIN", None),
            secure=getattr(settings, "LANGUAGE_COOKIE_SECURE", False),
            httponly=getattr(settings, "LANGUAGE_COOKIE_HTTPONLY", False),
            samesite=getattr(settings, "LANGUAGE_COOKIE_SAMESITE", "Lax"),
        )
        activate(lang_code)
    return response

from freedec.forms import (
    PublicDecryptDocumentForm,
    PublicPasswordRequestForm,
)
from freedec.services import DocumentManagementService



def get_client_ip(request):
    """Obtiene la IP remota del cliente considerando cabeceras de proxy inverso."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class PublicRequestGuiView(View):
    """
    Vista Web GUI pública para que los destinatarios suban su copia del archivo,
    ingresen su access_code y su correo electrónico para recibir la clave descifrada.
    """

    template_name = "freedec/public_request.html"

    def get(self, request):
        form = PublicPasswordRequestForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = PublicPasswordRequestForm(request.POST, request.FILES)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form}, status=400)

        uploaded_file = form.cleaned_data["file"]
        access_code = form.cleaned_data["access_code"]
        email = form.cleaned_data["email"]

        service = DocumentManagementService()
        decrypt_url = request.build_absolute_uri(reverse("freedec:gui-public-decrypt"))
        success, message = service.verify_and_dispatch_password(
            uploaded_file=uploaded_file,
            access_code=access_code,
            recipient_email=email,
            client_ip=get_client_ip(request),
            decrypt_url=decrypt_url,
        )

        context = {
            "form": PublicPasswordRequestForm(),  # Reset form
            "result_message": message,
            "is_success": success,
        }
        return render(request, self.template_name, context, status=200 if success else 500)


class PublicDecryptGuiView(View):
    """
    Vista Web GUI pública para que los destinatarios descifren y descarguen el documento original
    subiendo el archivo .enc y proporcionando la contraseña recibida por correo.
    """

    template_name = "freedec/public_decrypt.html"

    def get(self, request):
        form = PublicDecryptDocumentForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = PublicDecryptDocumentForm(request.POST, request.FILES)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form}, status=400)

        uploaded_file = form.cleaned_data["file"]
        password = form.cleaned_data["password"]

        service = DocumentManagementService()
        success, decrypted_bytes, suggested_filename, mimetype, message = (
            service.decrypt_document_with_password(
                encrypted_file_obj=uploaded_file,
                password=password,
                client_ip=get_client_ip(request),
            )
        )

        if not success:
            return render(
                request,
                self.template_name,
                {"form": form, "error_message": message},
                status=400,
            )

        # Entrega de descarga segura con tipo MIME adecuado y Content-Disposition
        response = HttpResponse(decrypted_bytes, content_type=mimetype or "application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{suggested_filename}"'
        return response
