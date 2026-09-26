import logging
from django.core.exceptions import ValidationError
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from freedec.serializers import (
    AdminDocumentUploadSerializer,
    PublicPasswordRequestSerializer,
)
from freedec.services import DocumentManagementService

logger = logging.getLogger(__name__)


class AdminDocumentUploadView(APIView):
    """
    Endpoint administrativo protegido para la subida y cifrado de documentos.
    
    Seguridad y Permisos:
    - permission_classes = [IsAuthenticated]: Requiere autenticación activa en el proyecto Django.
    - parser_classes = [MultiPartParser, FormParser]: Permite la recepción segura de archivos binarios.
    
    Respuesta:
    - Retorna el hash SHA-256 del archivo (clave unívoca de identificación criptográfica).
    - URL para la descarga del archivo cifrado.
    - access_code en texto plano (generado con 256 bits de entropía). Esta es la ÚNICA vez
      que se expone este código, ya que en base de datos se almacena su hash PBKDF2 (Zero-Knowledge).
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        serializer = AdminDocumentUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data
        original_file = validated_data["original_file"]
        plain_password = validated_data.get("plain_password") or None
        allowed_emails = validated_data["allowed_emails"]

        service = DocumentManagementService()

        try:
            document, raw_access_code = service.upload_and_encrypt_document(
                original_file=original_file,
                plain_password=plain_password,
                allowed_emails=allowed_emails,
            )
        except ValidationError as exc:
            return Response(
                {"error": str(exc.message if hasattr(exc, "message") else exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as exc:
            logger.exception(f"[FREEDEC ERROR] Fallo inesperado al procesar subida de documento: {exc}")
            return Response(
                {"error": "Ocurrió un error interno procesando y cifrando el documento."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        encrypted_file_url = None
        if document.encrypted_file:
            encrypted_file_url = request.build_absolute_uri(document.encrypted_file.url)

        response_data = {
            "status": "success",
            "message": "Documento cifrado y registrado exitosamente.",
            "file_hash": document.file_hash,
            "encrypted_file_url": encrypted_file_url,
            "access_code": raw_access_code,
            "generated_password": getattr(document, "generated_password", plain_password),
            "allowed_emails": document.allowed_emails,
            "created_at": document.created_at.isoformat(),
        }

        return Response(response_data, status=status.HTTP_201_CREATED)


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

        service = DocumentManagementService()
        success, message = service.verify_and_dispatch_password(
            uploaded_file=uploaded_file,
            access_code=access_code,
            recipient_email=email,
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
