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
    PublicAccessRequestForm,
    PublicConsumeDocumentForm,
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
    Vista Web GUI pública para que los destinatarios suban su copia del archivo .enc
    e introduzcan su correo electrónico para recibir el enlace mágico y código OTP temporal.
    """

    template_name = "freedec/public_request.html"

    def get(self, request):
        form = PublicAccessRequestForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = PublicAccessRequestForm(request.POST, request.FILES)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form}, status=400)

        uploaded_file = form.cleaned_data["file"]
        email = form.cleaned_data["email"]

        service = DocumentManagementService()
        base_url = request.build_absolute_uri("/").rstrip("/")
        success, message = service.request_document_access(
            uploaded_file=uploaded_file,
            recipient_email=email,
            client_ip=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT"),
            base_url=base_url,
        )

        context = {
            "form": PublicAccessRequestForm(),  # Reset form
            "result_message": message,
            "is_success": success,
        }
        return render(request, self.template_name, context, status=200 if success else 500)


class PublicConsumeGuiView(View):
    """
    Vista Web GUI pública para descifrar y consumir el documento original mediante
    el enlace mágico recibido por correo (?t=...) o mediante código OTP de 6 dígitos.
    Aplica la política destructiva Burn-after-read: el archivo en disco se elimina al instante.
    """

    template_name = "freedec/public_decrypt.html"

    def get(self, request):
        raw_token = request.GET.get("t")
        if raw_token:
            # Consumo directo mediante enlace mágico
            service = DocumentManagementService()
            success, decrypted_bytes, suggested_filename, mimetype, message = (
                service.consume_and_burn_document(
                    token_str=raw_token,
                    client_ip=get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT"),
                )
            )
            if success:
                response = HttpResponse(decrypted_bytes, content_type=mimetype or "application/octet-stream")
                response["Content-Disposition"] = f'attachment; filename="{suggested_filename}"'
                return response
            else:
                form = PublicConsumeDocumentForm()
                return render(
                    request,
                    self.template_name,
                    {"form": form, "error_message": message},
                    status=400,
                )

        form = PublicConsumeDocumentForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = PublicConsumeDocumentForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form}, status=400)

        token_str = form.cleaned_data.get("token") or request.GET.get("t")
        otp_code = form.cleaned_data.get("otp_code")
        email = form.cleaned_data.get("email")

        service = DocumentManagementService()
        success, decrypted_bytes, suggested_filename, mimetype, message = (
            service.consume_and_burn_document(
                token_str=token_str,
                otp_code=otp_code,
                email=email,
                client_ip=get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT"),
            )
        )

        if not success:
            return render(
                request,
                self.template_name,
                {"form": form, "error_message": message},
                status=400,
            )

        response = HttpResponse(decrypted_bytes, content_type=mimetype or "application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{suggested_filename}"'
        return response


def consume_document_view(request):
    """Función de vista para consumo y destrucción directa (Requisito 4)."""
    return PublicConsumeGuiView.as_view()(request)


# Alias de compatibilidad
PublicDecryptGuiView = PublicConsumeGuiView
