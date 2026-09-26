import logging
from django.urls import reverse
from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from freedec.serializers import (
    PublicAccessRequestSerializer,
    PublicConsumeSerializer,
    PublicPasswordRequestSerializer,
)
from freedec.services import DocumentManagementService

logger = logging.getLogger(__name__)


class PublicAccessRequestView(APIView):
    """
    Endpoint público para la solicitud de acceso a documentos mediante Enlace Mágico / OTP.
    
    Medidas de Ciberseguridad Aplicadas:
    - permission_classes = [AllowAny]: Acceso público para destinatarios autorizados.
    - throttle_classes = [AnonRateThrottle]: Limitación de tasa de peticiones.
    - Anti-Enumeration & Anti-Timing: Devuelve siempre una respuesta genérica neutra.
    """

    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]
    throttle_classes = [AnonRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = PublicAccessRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = serializer.validated_data["file"]
        email = serializer.validated_data["email"]

        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR"))
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

        service = DocumentManagementService()
        base_url = request.build_absolute_uri("/").rstrip("/")
        success, message = service.request_document_access(
            uploaded_file=uploaded_file,
            recipient_email=email,
            client_ip=ip,
            user_agent=request.META.get("HTTP_USER_AGENT"),
            base_url=base_url,
        )

        if not success:
            return Response(
                {"error": message},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                "status": "processed",
                "message": message,
            },
            status=status.HTTP_200_OK,
        )


class PublicConsumeView(APIView):
    """
    Endpoint para consumir y descifrar el documento mediante token URL o código OTP.
    Aplica política Burn-after-read: el archivo en disco se elimina al completar la petición.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def get(self, request, *args, **kwargs):
        token_str = request.query_params.get("t") or request.query_params.get("token")
        if not token_str:
            return Response({"error": "Debe especificar el token ?t="}, status=status.HTTP_400_BAD_REQUEST)

        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR"))
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

        service = DocumentManagementService()
        success, decrypted_bytes, filename, mimetype, message = service.consume_and_burn_document(
            token_str=token_str,
            client_ip=ip,
            user_agent=request.META.get("HTTP_USER_AGENT"),
        )
        if not success:
            return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)

        from django.http import HttpResponse
        response = HttpResponse(decrypted_bytes, content_type=mimetype or "application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    def post(self, request, *args, **kwargs):
        serializer = PublicConsumeSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token_str = serializer.validated_data.get("token")
        otp_code = serializer.validated_data.get("otp_code")
        email = serializer.validated_data.get("email")

        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR"))
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

        service = DocumentManagementService()
        success, decrypted_bytes, filename, mimetype, message = service.consume_and_burn_document(
            token_str=token_str,
            otp_code=otp_code,
            email=email,
            client_ip=ip,
            user_agent=request.META.get("HTTP_USER_AGENT"),
        )
        if not success:
            return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)

        from django.http import HttpResponse
        response = HttpResponse(decrypted_bytes, content_type=mimetype or "application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response


# Alias de compatibilidad
PublicPasswordRequestView = PublicAccessRequestView
