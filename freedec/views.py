import logging
from django.urls import reverse
from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from freedec.serializers import PublicPasswordRequestSerializer
from freedec.services import DocumentManagementService

logger = logging.getLogger(__name__)


class PublicPasswordRequestView(APIView):
    """
    Endpoint público para la verificación de documentos y recuperación automatizada de claves.
    
    Medidas de Ciberseguridad Aplicadas:
    - permission_classes = [AllowAny]: Acceso público para destinatarios autorizados.
    - throttle_classes = [AnonRateThrottle]: Limitación de tasa de peticiones para mitigar
      ataques de fuerza bruta contra el 'access_code' y ataques DoS.
    - Anti-Enumeration & Anti-Timing:
      El endpoint calcula el SHA-256 en runtime del archivo subido por el usuario.
      Si los datos son inválidos, ejecuta operaciones simuladas y devuelve una respuesta
      unificada neutra para que un atacante no pueda sondear qué archivos o correos existen.
    """

    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]
    throttle_classes = [AnonRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = PublicPasswordRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = serializer.validated_data["file"]
        access_code = serializer.validated_data["access_code"]
        email = serializer.validated_data["email"]

        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR"))
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

        service = DocumentManagementService()
        decrypt_url = request.build_absolute_uri(reverse("freedec:gui-public-decrypt"))
        success, message = service.verify_and_dispatch_password(
            uploaded_file=uploaded_file,
            access_code=access_code,
            recipient_email=email,
            client_ip=ip,
            decrypt_url=decrypt_url,
        )

        # Si ocurrió un error de infraestructura de correo o error de configuración
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
