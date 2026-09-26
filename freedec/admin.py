from django import forms
from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

from freedec.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from freedec.services import DocumentManagementService
from freedec.validators import normalize_and_validate_email_list, validate_document_file


def get_client_ip(request):
    """Obtiene la IP remota del cliente considerando cabeceras de proxy inverso."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class EmailListAdminWidget(forms.Widget):
    """
    Widget interactivo para Django Admin que permite gestionar correos electrónicos
    mediante campos de texto individuales con botones '+' y '✕'.
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
    El admin sube el archivo original y los correos autorizados.
    El sistema aplica el cifrado DEK multi-usuario y sobres individuales (user_envelopes).
    """

    original_file = forms.FileField(
        label=_("Archivo Documental Original"),
        help_text=_(
            "Formatos admitidos: PDF, LibreOffice (.odt, .ods, .odp, .odg) o Microsoft Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt)."
        ),
    )
    allowed_emails = forms.CharField(
        label=_("Correos Autorizados"),
        required=True,
        widget=EmailListAdminWidget(),
        help_text=_("Destinatarios autorizados a solicitar Enlace Mágico / OTP (sin JSON manual)."),
    )

    class Meta:
        model = EncryptedDocument
        fields = ("original_file", "allowed_emails")

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
    """Formulario de consulta/modificación en Django Admin."""

    allowed_emails = forms.CharField(
        label=_("Correos Autorizados"),
        required=True,
        widget=EmailListAdminWidget(),
        help_text=_("Destinatarios autorizados. Use '+' para añadir o modificar direcciones."),
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
    readonly_fields = ("timestamp", "email", "action_badge", "ip_address", "user_agent")
    fields = ("timestamp", "email", "action_badge", "ip_address", "user_agent")
    verbose_name = _("Registro de acceso")
    verbose_name_plural = _("Historial de auditoría y trazabilidad (DocumentAccessLog)")

    def has_add_permission(self, request, obj=None):
        return False

    @admin.display(description=_("Acción"))
    def action_badge(self, obj):
        colors = {
            "descifrado_completado_burn": ("#10b981", "#022c22"),
            "solicitud_acceso": ("#38bdf8", "#082f49"),
            "intento_post_consumo": ("#f59e0b", "#451a03"),
            "admin_inspeccion_preservada": ("#a855f7", "#3b0764"),
            "intento_fallido": ("#ef4444", "#450a0a"),
        }
        border, bg = colors.get(obj.action, ("#94a3b8", "#1e293b"))
        return format_html(
            '<span style="background:{}; color:#f8fafc; border:1px solid {}; padding:2px 8px; border-radius:12px; font-weight:bold; font-size:0.8rem;">{}</span>',
            bg,
            border,
            obj.action,
        )


class AccessVerificationTokenInline(admin.TabularInline):
    """Muestra los tokens de acceso y códigos OTP generados para el documento."""

    model = AccessVerificationToken
    extra = 0
    can_delete = False
    readonly_fields = ("created_at", "email", "otp_code", "expires_at", "status_badge")
    fields = ("created_at", "email", "otp_code", "expires_at", "status_badge")
    verbose_name = _("Token de verificación")
    verbose_name_plural = _("Tokens de acceso temporal (Magic Link / OTP)")

    def has_add_permission(self, request, obj=None):
        return False

    @admin.display(description=_("Estado"))
    def status_badge(self, obj):
        if obj.is_used:
            return mark_safe('<span style="color:#10b981; font-weight:bold;">✓ USADO</span>')
        if obj.is_expired():
            return mark_safe('<span style="color:#ef4444; font-weight:bold;">⌛ EXPIRADO</span>')
        return mark_safe('<span style="color:#38bdf8; font-weight:bold;">⏳ ACTIVO</span>')


@admin.register(EncryptedDocument)
class EncryptedDocumentAdmin(admin.ModelAdmin):
    """
    Panel de administración para EncryptedDocument integrado nativamente en Django Admin.
    """

    inlines = [DocumentAccessLogInline, AccessVerificationTokenInline]

    list_display = (
        "original_filename",
        "short_file_hash",
        "consumption_status_badge",
        "access_count",
        "last_accessed_at",
        "download_link",
        "admin_download_button",
        "delete_action_button",
    )
    list_filter = ("is_consumed", "created_at", "last_accessed_at")
    search_fields = ("original_filename", "file_hash", "consumed_by", "last_accessed_by")

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "<path:object_id>/admin-download/",
                self.admin_site.admin_view(self.admin_download),
                name="freedec_encrypteddocument_admin_download",
            ),
        ]
        return custom_urls + urls

    def get_inline_instances(self, request, obj=None):
        if obj is None:
            return []
        return super().get_inline_instances(request, obj)

    def get_form(self, request, obj=None, **kwargs):
        if obj is None:
            return EncryptedDocumentAddForm
        return EncryptedDocumentChangeForm

    def get_fieldsets(self, request, obj=None):
        if obj is None:
            return (
                (
                    _("Cifrado y Registro de Nuevo Documento"),
                    {
                        "fields": ("original_file", "allowed_emails"),
                        "description": _(
                            "Suba el archivo original y especifique los correos autorizados. El sistema generará la DEK simétrica y los sobres digitales de usuario."
                        ),
                    },
                ),
            )
        return (
            (
                _("Nombre e Identificación Criptográfica"),
                {
                    "fields": ("original_filename", "file_hash", "encrypted_file_hash"),
                    "description": _("Resúmenes SHA-256 calculados para el archivo original y el archivo cifrado en reposo."),
                },
            ),
            (
                _("Almacenamiento Cifrado y Descarga Administrativa"),
                {
                    "fields": ("encrypted_file", "admin_tools_panel"),
                    "description": _(
                        "El archivo binario se almacena en disco cifrado con la DEK. El botón permite descarga administrativa sin destrucción."
                    ),
                },
            ),
            (
                _("Ciclo de Vida y Destrucción (Burn-After-Read)"),
                {
                    "fields": ("is_consumed", "consumed_by", "consumed_at"),
                    "description": _(
                        "Control del ciclo de vida: cuando un usuario final descarga el archivo, este se destruye físicamente del disco."
                    ),
                },
            ),
            (
                _("Seguridad y Control de Acceso"),
                {
                    "fields": ("allowed_emails",),
                    "description": _(
                        "Lista de destinatarios autorizados para solicitar Enlace Mágico o código OTP."
                    ),
                },
            ),
            (
                _("Auditoría y Trazabilidad de Accesos"),
                {
                    "fields": (
                        "access_count",
                        "last_accessed_at",
                        "last_accessed_by",
                        "created_at",
                        "updated_at",
                    ),
                    "description": _(
                        "Registro de actividad y fecha del último acceso o despacho."
                    ),
                },
            ),
        )

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            return ()
        return (
            "original_filename",
            "file_hash",
            "encrypted_file_hash",
            "encrypted_file",
            "admin_tools_panel",
            "is_consumed",
            "consumed_by",
            "consumed_at",
            "access_count",
            "last_accessed_at",
            "last_accessed_by",
            "created_at",
            "updated_at",
        )

    def save_model(self, request, obj, form, change):
        if not change:
            service = DocumentManagementService()
            original_file = form.cleaned_data["original_file"]
            allowed_emails = form.cleaned_data["allowed_emails"]

            doc, _ = service.upload_and_encrypt_document(
                original_file=original_file,
                allowed_emails=allowed_emails,
            )

            obj.pk = doc.pk
            obj.id = doc.id
            obj.original_filename = doc.original_filename
            obj.file_hash = doc.file_hash
            obj.encrypted_file = doc.encrypted_file
            obj.encrypted_file_hash = doc.encrypted_file_hash
            obj.admin_encrypted_dek = doc.admin_encrypted_dek
            obj.user_envelopes = doc.user_envelopes
            obj.allowed_emails = doc.allowed_emails
            obj.is_consumed = doc.is_consumed
            obj.created_at = doc.created_at
            obj.updated_at = doc.updated_at
        else:
            super().save_model(request, obj, form, change)

    def response_add(self, request, obj, post_url_continue=None):
        download_html = ""
        if obj.encrypted_file:
            enc_name = f"{obj.original_filename}.enc"
            download_html = format_html(
                "<strong>📥 ARCHIVO CIFRADO (.ENC) PARA DISTRIBUCIÓN:</strong><br>"
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
                "<strong>🔐 ARQUITECTURA ZERO-TRUST (Magic Link / OTP):</strong><br>"
                "Se han generado sobres digitales individuales para {} destinatarios autorizados.<br>"
                "Cuando los destinatarios soliciten el acceso en el portal público, recibirán un enlace seguro y un código OTP temporal válido por 15 minutos.<br>"
                "<em>Al primer consumo por parte de cualquier usuario autorizado, el archivo en disco será destruido físicamente de forma automática (Burn-After-Read).</em>",
                obj.original_filename,
                obj.file_hash,
                download_html,
                len(obj.allowed_emails or []),
            ),
        )
        return super().response_add(request, obj, post_url_continue=post_url_continue)

    def admin_download(self, request, object_id):
        """Descarga administrativa sin destrucción (Audit Bypass)."""
        doc = self.get_object(request, object_id)
        if not doc:
            messages.error(request, _("El documento no existe."))
            return HttpResponseRedirect(reverse("admin:freedec_encrypteddocument_changelist"))

        if not self.has_change_permission(request, doc):
            raise PermissionDenied

        service = DocumentManagementService()
        success, decrypted_bytes, suggested_filename, mimetype, message = service.admin_decrypt_document(
            document=doc,
            admin_user=request.user,
            client_ip=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT"),
        )

        if not success:
            messages.warning(request, message)
            return HttpResponseRedirect(
                reverse("admin:freedec_encrypteddocument_change", args=[object_id])
            )

        response = HttpResponse(decrypted_bytes, content_type=mimetype or "application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{suggested_filename}"'
        return response

    @admin.display(description=_("Hash SHA-256"))
    def short_file_hash(self, obj):
        return f"{obj.file_hash[:12]}...{obj.file_hash[-6:]}"

    @admin.display(description=_("Estado"))
    def consumption_status_badge(self, obj):
        if obj.is_consumed:
            return format_html(
                '<span style="background:#450a0a; color:#f87171; border:1px solid #ef4444; padding:3px 10px; border-radius:12px; font-weight:bold; font-size:0.8rem;" title="Retirado el {}">🔥 Consumido por {}</span>',
                obj.consumed_at.strftime("%Y-%m-%d %H:%M UTC") if obj.consumed_at else "",
                obj.consumed_by or _("desconocido"),
            )
        return mark_safe(
            '<span style="background:#022c22; color:#34d399; border:1px solid #10b981; padding:3px 10px; border-radius:12px; font-weight:bold; font-size:0.8rem;">🟢 Activo (Listo para consumo)</span>'
        )

    @admin.display(description=_("Descargar Cifrado"))
    def download_link(self, obj):
        if obj.encrypted_file and not obj.is_consumed:
            enc_name = f"{obj.original_filename}.enc"
            return format_html(
                '<a href="{}" download="{}" class="button" style="padding: 4px 10px; font-size: 0.8rem; background: #0284c7; color: white; border-radius: 4px; text-decoration: none; font-weight: bold;">📥 .enc</a>',
                obj.encrypted_file.url,
                enc_name,
            )
        return mark_safe('<span style="color:#64748b;">—</span>')

    @admin.display(description=_("Copia Admin"))
    def admin_download_button(self, obj):
        if obj.is_consumed:
            return mark_safe('<span style="color:#ef4444; font-size:0.8rem;">Destruido</span>')
        url = reverse("admin:freedec_encrypteddocument_admin_download", args=[obj.pk])
        return format_html(
            '<a href="{}" class="button" style="background:#a855f7; color:white; padding:4px 10px; border-radius:4px; text-decoration:none; font-size:0.8rem; font-weight:bold;" title="Descargar copia descifrada original sin destruir el archivo">🔓 Original (Admin)</a>',
            url,
        )

    @admin.display(description=_("Eliminar"))
    def delete_action_button(self, obj):
        url = reverse("admin:freedec_encrypteddocument_delete", args=[obj.pk])
        return format_html(
            '<a class="button" href="{}" style="background-color: #ba2121; color: white; padding: 4px 10px; border-radius: 4px; text-decoration: none; font-size: 0.8rem; font-weight: bold;">🗑️</a>',
            url,
        )

    @admin.display(description=_("Herramientas de Personal Administrativo"))
    def admin_tools_panel(self, obj):
        if obj.is_consumed:
            return format_html(
                '<div style="background:#450a0a; border:1px solid #ef4444; padding:12px; border-radius:8px; color:#fca5a5;">'
                '<strong>🔥 DOCUMENTO CONSUMIDO Y DESTRUIDO:</strong><br>'
                'Este documento fue descargado por <strong>{}</strong> el <strong>{}</strong>.<br>'
                'El archivo físico ha sido eliminado del almacenamiento de forma permanente por la política Burn-After-Read.'
                '</div>',
                obj.consumed_by or "desconocido",
                obj.consumed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if obj.consumed_at else "",
            )

        url = reverse("admin:freedec_encrypteddocument_admin_download", args=[obj.pk])
        return format_html(
            '<div style="background:#1e1b4b; border:1px solid #6366f1; padding:12px; border-radius:8px; display:flex; justify-content:space-between; align-items:center;">'
            '<div>'
            '<strong style="color:#c7d2fe;">🔓 Descarga Administrativa Preservada (Audit Bypass):</strong><br>'
            '<span style="color:#94a3b8; font-size:0.85rem;">Descarga el archivo original descifrado. NO se destruirá el binario ni se marcará como consumido.</span>'
            '</div>'
            '<a href="{}" class="button" style="background:#6366f1; color:white; padding:8px 16px; border-radius:6px; font-weight:bold; text-decoration:none;">'
            '🔓 Descargar Original'
            '</a>'
            '</div>',
            url,
        )


@admin.register(DocumentAccessLog)
class DocumentAccessLogAdmin(admin.ModelAdmin):
    """
    Panel de auditoría histórica para ver todos los accesos a documentos y peticiones.
    """

    list_display = ("document", "email", "action", "ip_address", "user_agent", "timestamp")
    list_filter = ("action", "timestamp")
    search_fields = ("email", "document__original_filename", "document__file_hash", "ip_address")
    readonly_fields = ("document", "email", "action", "ip_address", "user_agent", "timestamp")

    def has_add_permission(self, request):
        return False


@admin.register(AccessVerificationToken)
class AccessVerificationTokenAdmin(admin.ModelAdmin):
    """
    Panel de visualización y control de tokens de acceso temporal (Magic Link / OTP).
    """

    list_display = ("document", "email", "otp_code", "created_at", "expires_at", "is_used")
    list_filter = ("is_used", "created_at")
    search_fields = ("email", "document__original_filename", "otp_code")
    readonly_fields = ("document", "email", "token_hash", "otp_code", "created_at", "expires_at", "is_used")

    def has_add_permission(self, request):
        return False
