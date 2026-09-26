from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from freedec.gui_views import (
    AdminUploadGuiView,
    PublicDecryptGuiView,
    PublicRequestGuiView,
)

urlpatterns = [
    # Panel de administración de Django
    path("admin/", admin.site.urls),
    # Portal Web HTML visual directamente accesible en la raíz
    path("", PublicRequestGuiView.as_view(), name="root-public-gui"),
    path("descifrar/", PublicDecryptGuiView.as_view(), name="root-public-decrypt-gui"),
    path("admin-upload/", AdminUploadGuiView.as_view(), name="root-admin-upload-gui"),
    # Endpoints y vistas bajo namespace de la aplicación Freedec
    path("api/freedec/", include("freedec.urls", namespace="freedec")),
]

# Servir archivos cifrados en desarrollo / staging
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
