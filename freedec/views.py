from __future__ import annotations

import io
import logging
from typing import Any, Optional, Tuple

from django.conf import settings
from django.contrib import messages
from django.http import FileResponse, HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import activate, check_for_language, gettext as _
from django.views import View
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from freedec.forms import RedeemOtpForm, RequestAccessForm
from freedec.serializers import PublicAccessRequestSerializer, PublicConsumeSerializer
from freedec.services import consume_document_with_otp, request_document_access

logger = logging.getLogger(__name__)


def get_client_ip(request: HttpRequest) -> Optional[str]:
    """Obtiene la dirección IP remota del cliente considerando proxies inversos."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def set_language_view(request: HttpRequest) -> HttpResponseRedirect:
    """Cambia el idioma activo de la interfaz y redirige a la vista previa."""
    lang_code = request.GET.get("lang") or request.POST.get("language")
    try:
        fallback_url = reverse("freedec:request-access")
    except Exception:
        fallback_url = "/freedec/solicitar/"

    next_url = request.GET.get("next") or request.META.get("HTTP_REFERER") or fallback_url
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


class RequestAccessView(View):
    """
    Vista Web GUI para solicitar acceso mediante Hash SHA-256 y OTP.
    
    Regla de Oro:
    El usuario final NUNCA sube el archivo .enc.
    El localizador oficial y prueba de trámite es exclusivamente el hash SHA-256.
    Soporta recibir ?hash=... por URL para auto-completar el formulario.
    """

    template_name = "freedec/public_request.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        initial = {}
        url_hash = request.GET.get("hash")
        if url_hash:
            initial["file_hash"] = url_hash.strip().lower()

        form = RequestAccessForm(initial=initial)
        return render(request, self.template_name, {"form": form})

    def post(self, request: HttpRequest) -> HttpResponse:
        form = RequestAccessForm(request.POST)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form}, status=400)

        file_hash = form.cleaned_data["file_hash"]
        email = form.cleaned_data["email"]

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")
        base_url = request.build_absolute_uri("/").rstrip("/")

        success, message = request_document_access(
            file_hash=file_hash,
            email=email,
            client_ip=client_ip,
            user_agent=user_agent,
            base_url=base_url,
        )

        request.session["freedec_file_hash"] = file_hash
        request.session["freedec_email"] = email
        messages.info(request, message)

        try:
            redeem_url = reverse("freedec:redeem-otp")
        except Exception:
            redeem_url = "/freedec/canjear/"

        return HttpResponseRedirect(f"{redeem_url}?hash={file_hash}")


class RedeemOtpView(View):
    """
    Vista Web GUI para el canje seguro mediante código OTP de 6 dígitos.
    
    Si el canje es exitoso, devuelve inmediatamente un FileResponse con los bytes
    descifrados en memoria RAM (io.BytesIO) y activa la política Burn-After-Read.
    """

    template_name = "freedec/public_decrypt.html"

    def _resolve_credentials(self, request: HttpRequest) -> Tuple[str, str]:
        file_hash = (
            request.GET.get("hash")
            or request.POST.get("file_hash")
            or request.session.get("freedec_file_hash")
            or ""
        ).strip().lower()

        email = (
            request.GET.get("email")
            or request.POST.get("email")
            or request.session.get("freedec_email")
            or ""
        ).strip().lower()

        return file_hash, email

    def get(self, request: HttpRequest) -> HttpResponse:
        file_hash, email = self._resolve_credentials(request)
        if not file_hash or not email:
            messages.warning(
                request,
                _("Debe solicitar el acceso con el identificador del documento antes de introducir el código de verificación."),
            )
            try:
                request_url = reverse("freedec:request-access")
            except Exception:
                request_url = "/freedec/solicitar/"
            return HttpResponseRedirect(request_url)

        form = RedeemOtpForm(initial={"file_hash": file_hash, "email": email})
        return render(
            request,
            self.template_name,
            {
                "form": form,
                "file_hash": file_hash,
                "email": email,
            },
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        file_hash, email = self._resolve_credentials(request)
        data = request.POST.copy()
        if not data.get("file_hash") and file_hash:
            data["file_hash"] = file_hash
        if not data.get("email") and email:
            data["email"] = email

        form = RedeemOtpForm(data)
        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "file_hash": file_hash,
                    "email": email,
                },
                status=400,
            )

        valid_hash = form.cleaned_data["file_hash"]
        valid_email = form.cleaned_data["email"]
        otp_code = form.cleaned_data["otp_code"]

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

        success, decrypted_bytes, original_filename, message = consume_document_with_otp(
            file_hash=valid_hash,
            email=valid_email,
            entered_otp=otp_code,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        if not success:
            return render(
                request,
                self.template_name,
                {
                    "form": form,
                    "error_message": message,
                    "file_hash": valid_hash,
                    "email": valid_email,
                },
                status=400,
            )

        # Limpiar credenciales de sesión tras el canje exitoso
        request.session.pop("freedec_file_hash", None)
        request.session.pop("freedec_email", None)

        response = FileResponse(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            filename=original_filename,
        )
        return response


# ==============================================================================
# ENDPOINTS REST API (DRF) PARA ACCESO DESATENDIDO
# ==============================================================================
class PublicAccessRequestView(APIView):
    """Endpoint REST para solicitar código OTP con hash SHA-256."""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        serializer = PublicAccessRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        file_hash = serializer.validated_data["file_hash"]
        email = serializer.validated_data["email"]

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")
        base_url = request.build_absolute_uri("/").rstrip("/")

        success, message = request_document_access(
            file_hash=file_hash,
            email=email,
            client_ip=client_ip,
            user_agent=user_agent,
            base_url=base_url,
        )

        return Response(
            {"status": "processed", "message": message},
            status=status.HTTP_200_OK,
        )


class PublicConsumeView(APIView):
    """Endpoint REST para canjear y descargar documento mediante OTP (Burn-After-Read)."""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        serializer = PublicConsumeSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        file_hash = serializer.validated_data["file_hash"]
        email = serializer.validated_data["email"]
        otp_code = serializer.validated_data["otp_code"]

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

        success, decrypted_bytes, original_filename, message = consume_document_with_otp(
            file_hash=file_hash,
            email=email,
            entered_otp=otp_code,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        if not success:
            return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)

        response = HttpResponse(decrypted_bytes, content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{original_filename}"'
        return response


# Alias de compatibilidad
PublicRequestGuiView = RequestAccessView
PublicConsumeGuiView = RedeemOtpView
PublicDecryptGuiView = RedeemOtpView
consume_document_view = RedeemOtpView.as_view()
PublicPasswordRequestView = PublicAccessRequestView
