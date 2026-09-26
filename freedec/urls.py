from django.urls import path

from freedec.gui_views import (
    PublicDecryptGuiView,
    PublicRequestGuiView,
    set_language_view,
)
from freedec.views import PublicPasswordRequestView

app_name = "freedec"

urlpatterns = [
    # ==========================================================================
    # INTERFAZ GRÁFICA DE USUARIO (WEB GUI)
    # ==========================================================================
    # Selector de idioma para internacionalización (i18n)
    path(
        "set-language/",
        set_language_view,
        name="set-language",
    ),
    # Portal público web para recuperación de contraseñas
    path(
        "",
        PublicRequestGuiView.as_view(),
        name="gui-public-request",
    ),
    # Portal público web para descifrar y descargar archivo .enc
    path(
        "descifrar/",
        PublicDecryptGuiView.as_view(),
        name="gui-public-decrypt",
    ),
    # ==========================================================================
    # ENDPOINTS DE LA API REST (DRF)
    # ==========================================================================
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
