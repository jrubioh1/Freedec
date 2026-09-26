from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    # Redirección dinámica de la raíz al portal base de Freedec (compatible con SCRIPT_NAME de Apache)
    path("", RedirectView.as_view(pattern_name="freedec:gui-public-request", permanent=False), name="root-redirect"),
    # Panel de administración de Django
    path("admin/", admin.site.urls),
    # Todas las URLs de Freedec agrupadas bajo el prefijo base 'freedec/'
    path("freedec/", include("freedec.urls", namespace="freedec")),
]

# Servir archivos cifrados en desarrollo / staging
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
