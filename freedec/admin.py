from django.contrib import admin
from django.utils.html import format_html
from freedec.models import EncryptedDocument


@admin.register(EncryptedDocument)
class EncryptedDocumentAdmin(admin.ModelAdmin):
    """
    Panel de administración para EncryptedDocument.
    
    Consideraciones de Ciberseguridad:
    - Los campos críticos (file_hash, access_code, encrypted_password) se configuran
      como de solo lectura para evitar modificaciones manuales no auditadas o alteración
      de los resúmenes criptográficos.
    - Se protege la visualización de datos sensibles.
    """

    list_display = (
        "short_file_hash",
        "allowed_emails_summary",
        "has_encrypted_file",
        "created_at",
    )
    list_filter = ("created_at",)
    search_fields = ("file_hash",)
    readonly_fields = (
        "file_hash",
        "access_code",
        "encrypted_password",
        "created_at",
        "updated_at",
    )

    fieldsets = (
        (
            "Identificación Criptográfica",
            {
                "fields": ("file_hash",),
                "description": "Hash SHA-256 del archivo original calculado en la subida.",
            },
        ),
        (
            "Almacenamiento Cifrado",
            {
                "fields": ("encrypted_file", "encrypted_password"),
                "description": "El archivo y la contraseña se encuentran cifrados en reposo con Fernet (AES-128-CBC + HMAC).",
            },
        ),
        (
            "Seguridad y Control de Acceso",
            {
                "fields": ("access_code", "allowed_emails"),
                "description": "El código de acceso se almacena mediante hash PBKDF2 (Zero-Knowledge).",
            },
        ),
        (
            "Auditoría y Trazabilidad",
            {
                "fields": ("created_at", "updated_at"),
            },
        ),
    )

    @admin.display(description="Hash SHA-256")
    def short_file_hash(self, obj):
        return f"{obj.file_hash[:16]}...{obj.file_hash[-8:]}"

    @admin.display(description="Correos Autorizados")
    def allowed_emails_summary(self, obj):
        count = len(obj.allowed_emails) if isinstance(obj.allowed_emails, list) else 0
        return f"{count} correo(s) registrado(s)"

    @admin.display(boolean=True, description="Archivo en disco")
    def has_encrypted_file(self, obj):
        return bool(obj.encrypted_file)
