from django.urls import path

from freedec.gui_views import (
    PublicConsumeGuiView,
    PublicDecryptGuiView,
    PublicRequestGuiView,
    consume_document_view,
    set_language_view,
)
from freedec.views import PublicAccessRequestView, PublicConsumeView, PublicPasswordRequestView

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
    # Portal público web para solicitar acceso mediante Enlace Mágico / OTP
    path(
        "",
        PublicRequestGuiView.as_view(),
        name="gui-public-request",
    ),
    path(
        "solicitar/",
        PublicRequestGuiView.as_view(),
        name="request-access",
    ),
    # Portal público web para consumir y descargar archivo original (Burn-After-Read)
    path(
        "consumir/",
        PublicConsumeGuiView.as_view(),
        name="gui-consume",
    ),
    path(
        "consumir/directo/",
        consume_document_view,
        name="consume-document",
    ),
    path(
        "descifrar/",
        PublicDecryptGuiView.as_view(),
        name="gui-public-decrypt",
    ),
    # ==========================================================================
    # ENDPOINTS DE LA API REST (DRF)
    # ==========================================================================
    path(
        "public/request-access/",
        PublicAccessRequestView.as_view(),
        name="public-request-access",
    ),
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
    path(
        "api/public/consume/",
        PublicConsumeView.as_view(),
        name="api-public-consume",
    ),
]
