import re
from typing import Any, Dict
from django.conf import settings
from rest_framework import serializers

from freedec.validators import validate_safe_email

HASH_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


class PublicAccessRequestSerializer(serializers.Serializer):
    """
    Serializador REST para solicitud desatendida mediante Hash SHA-256 y correo.
    Regla de Oro: Cero transporte del binario por el cliente.
    """

    file_hash = serializers.CharField(
        required=True,
        max_length=64,
        min_length=64,
        help_text="Hash SHA-256 (64 hex) del documento confidencial.",
    )
    email = serializers.CharField(
        required=True,
        help_text="Correo electrónico oficial del solicitante.",
    )

    def validate_file_hash(self, value: str) -> str:
        clean = (value or "").strip().lower()
        if not HASH_REGEX.match(clean):
            raise serializers.ValidationError("El hash SHA-256 debe componerse exactamente de 64 caracteres hexadecimales.")
        return clean

    def validate_email(self, value: str) -> str:
        try:
            return validate_safe_email(value)
        except Exception as exc:
            raise serializers.ValidationError(str(exc))


class PublicConsumeSerializer(serializers.Serializer):
    """
    Serializador REST para canjear documento mediante OTP de 6 dígitos.
    """

    file_hash = serializers.CharField(
        required=True,
        max_length=64,
        min_length=64,
        help_text="Hash SHA-256 del documento.",
    )
    email = serializers.CharField(
        required=True,
        help_text="Correo electrónico del solicitante.",
    )
    otp_code = serializers.CharField(
        required=True,
        max_length=6,
        min_length=6,
        help_text="Código OTP de 6 dígitos.",
    )

    def validate_file_hash(self, value: str) -> str:
        clean = (value or "").strip().lower()
        if not HASH_REGEX.match(clean):
            raise serializers.ValidationError("Hash SHA-256 inválido.")
        return clean

    def validate_email(self, value: str) -> str:
        try:
            return validate_safe_email(value)
        except Exception as exc:
            raise serializers.ValidationError(str(exc))

    def validate_otp_code(self, value: str) -> str:
        clean = (value or "").strip()
        if not clean.isdigit() or len(clean) != 6:
            raise serializers.ValidationError("El código OTP debe ser numérico de 6 dígitos.")
        return clean


# Alias de compatibilidad
PublicPasswordRequestSerializer = PublicAccessRequestSerializer
