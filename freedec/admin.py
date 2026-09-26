from django import forms
from django.contrib import admin, messages
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe

from freedec.models import DocumentAccessLog, EncryptedDocument
from freedec.services import DocumentManagementService
from freedec.validators import normalize_and_validate_email_list, validate_document_file


class EmailListAdminWidget(forms.Widget):
    """
    Widget interactivo para Django Admin que permite gestionar correos electrónicos
    mediante campos de texto individuales con botones '+' y '✕', evitando la edición
    manual de arrays JSON.
    """

    def render(self, name, value, attrs=None, renderer=None):
        if value is None:
            email_list = []
        elif isinstance(value, list):
            email_list = value
        elif isinstance(value, str):
            try:
                import json
                parsed = json.loads(value)
                email_list = parsed if isinstance(parsed, list) else [value]
            except Exception:
                email_list = [e.strip() for e in value.split(",") if e.strip()]
        else:
            email_list = []

        if not email_list:
            email_list = [""]

        rows_html = []
        for val in email_list:
            safe_val = str(val).replace('"', '&quot;')
            rows_html.append(
                f'<div class="admin-email-row" style="display:flex; gap:8px; margin-bottom:6px; align-items:center;">'
                f'<input type="email" name="{name}" value="{safe_val}" class="vTextField" style="max-width:380px; width:100%;" placeholder="usuario@empresa.com" required>'
                f'<button type="button" class="button btn-remove-row" onclick="removeAdminRow(this)" style="background:#ba2121; color:#fff; border:none; border-radius:4px; padding:4px 10px; cursor:pointer;" title="Eliminar correo">✕</button>'
                f'</div>'
            )

        rows_rendered = "\n".join(rows_html)

        html = f"""
        <div id="{name}_admin_wrapper" style="width:100%; max-width:500px;">
            <div id="{name}_rows_container">
                {rows_rendered}
            </div>
            <div style="margin-top:8px;">
                <button type="button" class="button" onclick="addAdminRow('{name}')" style="background:#417690; color:#fff; border:none; border-radius:4px; padding:5px 12px; cursor:pointer; font-weight:bold;">
                    ➕ Añadir otro correo
                </button>
            </div>
        </div>
        <script>
            function addAdminRow(fieldName) {{
                const container = document.getElementById(fieldName + '_rows_container');
                if (!container) return;
                const row = document.createElement('div');
                row.className = 'admin-email-row';
                row.style.cssText = 'display:flex; gap:8px; margin-bottom:6px; align-items:center;';
                row.innerHTML = `
                    <input type="email" name="${{fieldName}}" value="" class="vTextField" style="max-width:380px; width:100%;" placeholder="usuario@empresa.com" required>
                    <button type="button" class="button btn-remove-row" onclick="removeAdminRow(this)" style="background:#ba2121; color:#fff; border:none; border-radius:4px; padding:4px 10px; cursor:pointer;" title="Eliminar correo">✕</button>
                `;
                container.appendChild(row);
                updateAdminRowControls(fieldName);
                const input = row.querySelector('input');
                if (input) input.focus();
            }}

            function removeAdminRow(btn) {{
                const row = btn.closest('.admin-email-row');
                const container = row.parentElement;
                const rows = container.getElementsByClassName('admin-email-row');
                if (rows.length > 1) {{
                    row.remove();
                    const wrapper = container.closest('[id$="_admin_wrapper"]');
                    if (wrapper) {{
                        const fieldName = wrapper.id.replace('_admin_wrapper', '');
                        updateAdminRowControls(fieldName);
                    }}
                }}
            }}

            function updateAdminRowControls(fieldName) {{
                const container = document.getElementById(fieldName + '_rows_container');
                if (!container) return;
                const rows = container.getElementsByClassName('admin-email-row');
                for (let i = 0; i < rows.length; i++) {{
                    const btn = rows[i].querySelector('.btn-remove-row');
                    if (btn) {{
                        btn.style.display = rows.length === 1 ? 'none' : 'inline-block';
                    }}
                }}
            }}

            document.addEventListener('DOMContentLoaded', function() {{
                updateAdminRowControls('{name}');
            }});
        </script>
        """
        return mark_safe(html)

    def value_from_datadict(self, data, files, name):
        if hasattr(data, "getlist"):
            return data.getlist(name)
        val = data.get(name)
        return [val] if val else []


class EncryptedDocumentAddForm(forms.ModelForm):
    """
    Formulario de alta para Django Admin:
    El admin sube el archivo original, la contraseña en plano y los correos autorizados.
    El sistema se encarga de aplicar el cifrado AES-Fernet, computar el hash SHA-256
    y derivar el código Zero-Knowledge.
    """

    original_file = forms.FileField(
        label="Archivo Documental Original",
        help_text="Formatos admitidos: PDF, LibreOffice (.odt, .ods, .odp, .odg) o Microsoft Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt).",
    )
    plain_password = forms.CharField(
        label="Contraseña (Opcional)",
        required=False,
        widget=forms.PasswordInput(
            attrs={"placeholder": "Dejar en blanco para autogenerar una clave segura..."}
        ),
        help_text="Opcional. Si se deja en blanco, el sistema genera automáticamente una clave de 24 caracteres.",
    )
    allowed_emails = forms.CharField(
        label="Correos Autorizados",
        required=True,
        widget=EmailListAdminWidget(),
        help_text="Destinatarios autorizados. Use '+' para añadir más direcciones (sin JSON).",
    )

    class Meta:
        model = EncryptedDocument
        fields = ("original_file", "plain_password", "allowed_emails")

    def clean_original_file(self):
        file_obj = self.cleaned_data.get("original_file")
        if not file_obj:
            raise forms.ValidationError("Debe seleccionar un archivo.")
        return validate_document_file(file_obj)

    def clean_allowed_emails(self):
        if hasattr(self.data, "getlist"):
            raw_entries = self.data.getlist("allowed_emails")
        else:
            raw_val = self.cleaned_data.get("allowed_emails") or self.data.get("allowed_emails") or ""
            raw_entries = [raw_val] if isinstance(raw_val, str) else list(raw_val)

        return normalize_and_validate_email_list(raw_entries)


class EncryptedDocumentChangeForm(forms.ModelForm):
    """
    Formulario de consulta/modificación en Django Admin:
    Permite modificar o añadir correos con el widget '+' y consultar los datos criptográficos.
    """

    allowed_emails = forms.CharField(
        label="Correos Autorizados",
        required=True,
        widget=EmailListAdminWidget(),
        help_text="Destinatarios autorizados. Use '+' para añadir o modificar direcciones.",
    )

    class Meta:
        model = EncryptedDocument
        fields = "__all__"

    def clean_allowed_emails(self):
        if hasattr(self.data, "getlist"):
            raw_entries = self.data.getlist("allowed_emails")
        else:
            raw_val = self.cleaned_data.get("allowed_emails") or self.data.get("allowed_emails") or ""
            raw_entries = [raw_val] if isinstance(raw_val, str) else list(raw_val)

        return normalize_and_validate_email_list(raw_entries)


class DocumentAccessLogInline(admin.TabularInline):
    """Muestra el historial y la auditoría de accesos dentro de la vista del documento."""

    model = DocumentAccessLog
    extra = 0
    can_delete = False
    readonly_fields = ("email", "action", "ip_address", "timestamp")
    fields = ("timestamp", "email", "action", "ip_address")
    verbose_name = "Registro de acceso"
    verbose_name_plural = "Historial de accesos y trazabilidad de clave"

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(EncryptedDocument)
class EncryptedDocumentAdmin(admin.ModelAdmin):
    """
    Panel de administración para EncryptedDocument integrado nativamente en Django Admin.
    """

    inlines = [DocumentAccessLogInline]

    list_display = (
        "original_filename",
        "short_file_hash",
        "access_count",
        "last_accessed_at",
        "last_accessed_by",
        "download_link",
        "delete_action_button",
    )
    list_filter = ("created_at", "last_accessed_at")
    search_fields = ("original_filename", "file_hash", "last_accessed_by")

    def get_form(self, request, obj=None, **kwargs):
        if obj is None:
            return EncryptedDocumentAddForm
        return EncryptedDocumentChangeForm

    def get_fieldsets(self, request, obj=None):
        if obj is None:
            return (
                (
                    "Cifrado y Registro de Nuevo Documento",
                    {
                        "fields": ("original_file", "plain_password", "allowed_emails"),
                        "description": "Suba el archivo original. La contraseña y el código de acceso se generarán automáticamente mediante algoritmos de alta entropía.",
                    },
                ),
            )
        return (
            (
                "Nombre e Identificación Criptográfica",
                {
                    "fields": ("original_filename", "file_hash"),
                    "description": "Nombre original y hash SHA-256 del archivo calculado en la subida.",
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
                    "description": "El código de acceso se almacena mediante hash PBKDF2 (Zero-Knowledge). Los correos pueden modificarse usando el botón '+'.",
                },
            ),
            (
                "Auditoría y Trazabilidad de Accesos",
                {
                    "fields": (
                        "access_count",
                        "last_accessed_at",
                        "last_accessed_by",
                        "created_at",
                        "updated_at",
                    ),
                    "description": "Registro de actividad y fecha del último acceso o despacho de contraseña.",
                },
            ),
        )

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            return ()
        return (
            "original_filename",
            "file_hash",
            "encrypted_file",
            "encrypted_password",
            "access_code",
            "access_count",
            "last_accessed_at",
            "last_accessed_by",
            "created_at",
            "updated_at",
        )

    def save_model(self, request, obj, form, change):
        if not change:
            # Creación a través de la tubería criptográfica completa
            service = DocumentManagementService()
            original_file = form.cleaned_data["original_file"]
            plain_password = form.cleaned_data.get("plain_password") or None
            allowed_emails = form.cleaned_data["allowed_emails"]

            doc, raw_access_code = service.upload_and_encrypt_document(
                original_file=original_file,
                plain_password=plain_password,
                allowed_emails=allowed_emails,
            )

            obj.pk = doc.pk
            obj.id = doc.id
            obj.original_filename = doc.original_filename
            obj.file_hash = doc.file_hash
            obj.encrypted_file = doc.encrypted_file
            obj.access_code = doc.access_code
            obj.encrypted_password = doc.encrypted_password
            obj.allowed_emails = doc.allowed_emails
            obj.created_at = doc.created_at
            obj.updated_at = doc.updated_at

            # Adjuntar código y contraseña para el mensaje flash
            request._raw_access_code = raw_access_code
            request._raw_password = getattr(doc, "generated_password", plain_password)
        else:
            super().save_model(request, obj, form, change)

    def response_add(self, request, obj, post_url_continue=None):
        raw_code = getattr(request, "_raw_access_code", None)
        raw_pwd = getattr(request, "_raw_password", None)
        if raw_code:
            pwd_html = ""
            if raw_pwd:
                pwd_html = format_html(
                    "<strong>🔐 CONTRASEÑA ASIGNADA / GENERADA:</strong><br>"
                    "<div style='font-size: 1.15rem; font-family: monospace; background: #0f172a; color: #34d399; padding: 10px; border-radius: 6px; margin: 6px 0; border: 1px solid #10b981; user-select: all;'>"
                    "<strong>{}</strong>"
                    "</div><br>",
                    raw_pwd,
                )

            download_html = ""
            if obj.encrypted_file:
                enc_name = f"{obj.original_filename}.enc"
                download_html = format_html(
                    "<strong>📥 ARCHIVO CIFRADO PARA DISTRIBUCIÓN:</strong><br>"
                    "<div style='margin: 8px 0;'>"
                    "<a href='{}' download='{}' class='button' style='background: #0284c7; color: white; padding: 6px 14px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;'>"
                    "📥 Descargar Archivo Cifrado ({})"
                    "</a>"
                    "</div><br>",
                    obj.encrypted_file.url,
                    enc_name,
                    enc_name,
                )

            messages.success(
                request,
                format_html(
                    "<strong>✅ Documento '{}' cifrado y registrado exitosamente (SHA-256: {})</strong><br><br>"
                    "{}"
                    "<strong>🔑 CÓDIGO SECRETO DE ACCESO (Zero-Knowledge):</strong><br>"
                    "<div style='font-size: 1.15rem; font-family: monospace; background: #0f172a; color: #fde68a; padding: 10px; border-radius: 6px; margin: 6px 0; border: 1px solid #f59e0b; user-select: all;'>"
                    "<strong>{}</strong>"
                    "</div><br>"
                    "{}"
                    "<em>⚠️ Guarde y entregue el código de acceso al destinatario por canal seguro (Signal, SMS o en persona). La contraseña le será enviada por correo cuando la solicite.</em>",
                    obj.original_filename,
                    obj.file_hash,
                    download_html,
                    raw_code,
                    pwd_html,
                ),
            )
        return super().response_add(request, obj, post_url_continue=post_url_continue)

    @admin.display(description="Hash SHA-256")
    def short_file_hash(self, obj):
        return f"{obj.file_hash[:12]}...{obj.file_hash[-6:]}"

    @admin.display(description="Descargar Cifrado")
    def download_link(self, obj):
        if obj.encrypted_file:
            enc_name = f"{obj.original_filename}.enc"
            return format_html(
                '<a href="{}" download="{}" class="button" style="padding: 4px 10px; font-size: 0.8rem; background: #0284c7; color: white; border-radius: 4px; text-decoration: none; font-weight: bold;">📥 {}</a>',
                obj.encrypted_file.url,
                enc_name,
                enc_name,
            )
        return "—"

    @admin.display(description="Eliminar")
    def delete_action_button(self, obj):
        url = reverse("admin:freedec_encrypteddocument_delete", args=[obj.pk])
        return format_html(
            '<a class="button" href="{}" style="background-color: #ba2121; color: white; padding: 4px 10px; border-radius: 4px; text-decoration: none; font-size: 0.8rem; font-weight: bold;">🗑️ Eliminar</a>',
            url,
        )


@admin.register(DocumentAccessLog)
class DocumentAccessLogAdmin(admin.ModelAdmin):
    """
    Panel de auditoría histórica para ver todos los accesos a documentos y peticiones de claves.
    """

    list_display = ("document", "email", "action", "ip_address", "timestamp")
    list_filter = ("action", "timestamp")
    search_fields = ("email", "document__original_filename", "document__file_hash", "ip_address")
    readonly_fields = ("document", "email", "action", "ip_address", "timestamp")

    def has_add_permission(self, request):
        return False
