from django.urls import path
from freedec.views import (
    PublicAccessRequestView,
    PublicConsumeView,
    PublicPasswordRequestView,
    RedeemOtpView,
    RequestAccessView,
    set_language_view,
)

app_name = "freedec"

urlpatterns = [
    # ==========================================================================
    # INTERFAZ GRÁFICA DE USUARIO (WEB GUI)
    # ==========================================================================
    # 1. Solicitud de acceso desatendido mediante Hash SHA-256 y OTP
    path(
        "solicitar/",
        RequestAccessView.as_view(),
        name="request-access",
    ),
    # 2. Canje y verificación en tiempo real mediante OTP de 6 dígitos
    path(
        "canjear/",
        RedeemOtpView.as_view(),
        name="redeem-otp",
    ),
    # Selector de idioma para internacionalización (i18n)
    path(
        "set-language/",
        set_language_view,
        name="set-language",
    ),
    # Rutas por defecto y alias de compatibilidad
    path(
        "",
        RequestAccessView.as_view(),
        name="gui-public-request",
    ),
    path(
        "consumir/",
        RedeemOtpView.as_view(),
        name="gui-consume",
    ),
    path(
        "descifrar/",
        RedeemOtpView.as_view(),
        name="gui-public-decrypt",
    ),
    # ==========================================================================
    # ENDPOINTS DE LA API REST (DRF)
    # ==========================================================================
    path(
        "api/public/request-access/",
        PublicAccessRequestView.as_view(),
        name="api-public-request-access",
    ),
    path(
        "api/public/consume/",
        PublicConsumeView.as_view(),
        name="api-public-consume",
    ),
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
]
