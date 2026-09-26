from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    # Panel de administración de Django
    path("admin/", admin.site.urls),
    # Endpoints de la aplicación Freedec
    path("api/freedec/", include("freedec.urls", namespace="freedec")),
]

# Servir archivos cifrados en desarrollo / staging
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
