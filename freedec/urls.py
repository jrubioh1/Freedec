from django.urls import path

from freedec.gui_views import AdminUploadGuiView, PublicRequestGuiView
from freedec.views import AdminDocumentUploadView, PublicPasswordRequestView

app_name = "freedec"

urlpatterns = [
    # ==========================================================================
    # INTERFAZ GRÁFICA DE USUARIO (WEB GUI)
    # ==========================================================================
    # Portal público web para recuperación de contraseñas
    path(
        "",
        PublicRequestGuiView.as_view(),
        name="gui-public-request",
    ),
    # Portal administrativo web para subida y cifrado (requiere autenticación)
    path(
        "admin-upload/",
        AdminUploadGuiView.as_view(),
        name="gui-admin-upload",
    ),
    # ==========================================================================
    # ENDPOINTS DE LA API REST (DRF)
    # ==========================================================================
    # Endpoint administrativo protegido para subida, cálculo SHA-256 y cifrado
    path(
        "admin/upload/",
        AdminDocumentUploadView.as_view(),
        name="admin-upload",
    ),
    path(
        "api/admin/upload/",
        AdminDocumentUploadView.as_view(),
        name="api-admin-upload",
    ),
    # Endpoint público con rate limiting para verificación de hash y despacho
    path(
        "public/request-password/",
        PublicPasswordRequestView.as_view(),
        name="public-request-password",
    ),
    path(
        "api/public/request-password/",
        PublicPasswordRequestView.as_view(),
        name="api-public-request-password",
    ),
]
