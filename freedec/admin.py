import io
import json
from typing import Any, List, Optional
from urllib.parse import quote

from django import forms
from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied
from django.http import FileResponse, Http404, HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

from freedec.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from freedec.services import (
    admin_decrypt_document,
    calculate_file_sha256,
    generate_corporate_email_text,
    reactivate_document,
    shred_and_delete_file,
    upload_and_encrypt_document,
)
from freedec.validators import normalize_and_validate_email_list, validate_document_file
from freedec.views import get_client_ip


class EmailListAdminWidget(forms.Widget):
    """
    Widget interactivo para Django Admin que permite gestionar correos autorizados
    mediante campos dinámicos individuales con botones '➕' y '✕'.
    """

    def render(self, name: str, value: Any, attrs: Optional[dict] = None, renderer: Any = None) -> Any:
        if value is None:
            email_list = []
        elif isinstance(value, list):
            email_list = value
        elif isinstance(value, str):
            try:
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
            safe_val = str(val).replace('"', "&quot;")
            rows_html.append(
                f'<div class="admin-email-row" style="display:flex; gap:8px; margin-bottom:6px; align-items:center;">'
                f'<input type="email" name="{name}" value="{safe_val}" class="vTextField" style="max-width:380px; width:100%;" placeholder="destinatario@empresa.com" required>'
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
                    ➕ Añadir otro correo autorizado
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
                    <input type="email" name="${{fieldName}}" value="" class="vTextField" style="max-width:380px; width:100%;" placeholder="destinatario@empresa.com" required>
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

            window.addEmailToAdminWidget = function(fieldName, email) {{
                const container = document.getElementById(fieldName + '_rows_container');
                if (!container) return;
                const inputs = container.querySelectorAll('input[name="' + fieldName + '"]');
                for (let i = 0; i < inputs.length; i++) {{
                    if (!inputs[i].value.trim()) {{
                        inputs[i].value = email;
                        updateAdminRowControls(fieldName);
                        return;
                    }}
                    if (inputs[i].value.trim().toLowerCase() === email.trim().toLowerCase()) {{
                        return;
                    }}
                }}
                addAdminRow(fieldName);
                const updatedInputs = container.querySelectorAll('input[name="' + fieldName + '"]');
                const last = updatedInputs[updatedInputs.length - 1];
                if (last) last.value = email;
                updateAdminRowControls(fieldName);
            }};

            document.addEventListener('DOMContentLoaded', function() {{
                updateAdminRowControls('{name}');
            }});
        </script>
        """
        return mark_safe(html)

    def value_from_datadict(self, data: Any, files: Any, name: str) -> Any:
        if hasattr(data, "getlist"):
            return data.getlist(name)
        val = data.get(name)
        return [val] if val else []


class HashingFileInputWidget(forms.ClearableFileInput):
    """
    Widget de subida con detección automática instantánea del hash SHA-256 en el cliente.
    Si el archivo ya existe en el sistema, muestra un aviso inmediato con enlace para abrirlo
    y advierte proactivamente si existen destinatarios pendientes de acceder.
    """

    def render(self, name: str, value: Any, attrs: Optional[dict] = None, renderer: Any = None) -> Any:
        base_html = super().render(name, value, attrs, renderer)
        input_id = (attrs or {}).get("id", f"id_{name}")
        try:
            check_url = reverse("admin:freedec_encrypteddocument_check_hash")
        except Exception:
            check_url = "/admin/freedec/encrypteddocument/check-file-hash/"

        script_html = f"""
        <div id="{input_id}_notice_container" style="margin-top:8px;"></div>
        <script>
        (function() {{
            const input = document.getElementById("{input_id}");
            if (!input) return;
            input.addEventListener('change', async function() {{
                const container = document.getElementById("{input_id}_notice_container");
                if (!container) return;
                container.innerHTML = '';
                if (!this.files || !this.files[0]) return;
                const file = this.files[0];
                try {{
                    const buffer = await file.arrayBuffer();
                    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    
                    const resp = await fetch('{check_url}?hash=' + hashHex);
                    if (!resp.ok) return;
                    const data = await resp.json();
                    if (data.exists) {{
                        const statusBadge = data.is_consumed 
                            ? '<span style="background:#ef4444; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.75rem; font-weight:bold;">🔥 Consumido</span>'
                            : '<span style="background:#10b981; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.75rem; font-weight:bold;">🟢 Activo</span>';
                        
                        let pendingWarningHtml = '';
                        if (data.pending_recipients && data.pending_recipients.length > 0) {{
                            const pendingList = data.pending_recipients.map(e => '<code style=\"background:#78350f; padding:1px 6px; border-radius:4px;\">' + e + '</code>').join(' ');
                            pendingWarningHtml = `
                                <div style="background:#451a03; border:2px solid #f59e0b; padding:10px 14px; border-radius:6px; margin:12px 0; color:#fef3c7;">
                                    <div style="font-weight:bold; color:#fbbf24; font-size:0.95rem; margin-bottom:4px; display:flex; align-items:center; gap:6px;">
                                        <span>⚠️</span> ¡ATENCIÓN! Este documento aún no ha finalizado (accesos pendientes):
                                    </div>
                                    <div style="font-size:0.88rem; margin-bottom:8px; line-height:1.4;">
                                        Faltan por acceder: ${{pendingList}}.<br>
                                        Al reactivar con nuevos destinatarios, los anteriores pierden el acceso a menos que los vuelva a añadir a la lista.
                                    </div>
                                    <button type="button" id="${{input.id}}_btn_add_pending" class="button" style="background:#d97706; color:#fff; border:none; padding:5px 12px; border-radius:4px; font-size:0.82rem; font-weight:bold; cursor:pointer;">
                                        ➕ Volver a añadir pendientes a la lista de correos
                                    </button>
                                </div>
                            `;
                        }}

                        container.innerHTML = `
                            <div style="background:#082f49; border:1px solid #0284c7; padding:14px; border-radius:8px; color:#e0f2fe; margin-top:8px;">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                                    <strong style="color:#38bdf8; font-size:0.95rem;">ℹ️ Archivo ya registrado en el sistema:</strong>
                                    ${{statusBadge}}
                                </div>
                                <div>Se localizó el registro existente para <strong>${{data.filename}}</strong> (registrado el ${{data.created_at}}).</div>
                                ${{pendingWarningHtml}}
                                <div style="margin-top:10px; display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
                                    <a href="${{data.change_url}}" class="button" style="background:#0284c7; color:#fff; padding:6px 14px; border-radius:4px; font-weight:bold; text-decoration:none; display:inline-block;">
                                        ↗️ Abrir registro existente directamente
                                    </a>
                                    <span style="font-size:0.85rem; color:#bae6fd;">
                                        O bien introduzca nuevos correos abajo y guarde: se reactivará automáticamente el registro existente conservando todo el historial.
                                    </span>
                                </div>
                            </div>
                        `;

                        if (data.pending_recipients && data.pending_recipients.length > 0) {{
                            const btn = document.getElementById(input.id + '_btn_add_pending');
                            if (btn) {{
                                btn.addEventListener('click', function() {{
                                    if (window.addEmailToAdminWidget) {{
                                        data.pending_recipients.forEach(em => window.addEmailToAdminWidget('allowed_emails', em));
                                        btn.innerText = '✓ Destinatarios pendientes añadidos';
                                        btn.style.background = '#059669';
                                        btn.disabled = true;
                                    }}
                                }});
                            }}
                        }}
                    }}
                }} catch (e) {{
                    console.log("[Freedec Hash Check Error]", e);
                }}
            }});
        }})();
        </script>
        """
        return mark_safe(base_html + script_html)


class EncryptedDocumentAddForm(forms.ModelForm):
    """
    Formulario de registro y cifrado de documentos en Django Admin.
    Cero contraseñas humanas: el sistema genera la DEK interna y cifra automáticamente.
    """

    original_file = forms.FileField(
        label=_("Archivo confidencial original"),
        widget=HashingFileInputWidget(),
        help_text=_(
            "Formatos admitidos: PDF, LibreOffice (.odt, .ods, .odp, .odg) o Microsoft Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt)."
        ),
    )
    description = forms.CharField(
        label=_("Descripción del documento"),
        required=False,
        initial="Documento confidencial tramitado a través de la pasarela segura Freedec.",
        widget=forms.Textarea(
            attrs={
                "rows": 3,
                "class": "vLargeTextField",
                "placeholder": _("Descripción informativa o motivo confidencial del trámite..."),
            }
        ),
        help_text=_(
            "Descripción que se incluirá en las notificaciones por correo y en la plantilla corporativa."
        ),
    )
    allowed_emails = forms.CharField(
        label=_("Correos autorizados"),
        widget=EmailListAdminWidget(),
        help_text=_("Direcciones de correo autorizadas para solicitar el canje con OTP."),
    )
    burn_policy = forms.ChoiceField(
        label=_("Política de Destrucción"),
        choices=EncryptedDocument.BurnPolicy.choices,
        initial=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        required=False,
        widget=forms.RadioSelect,
        help_text=_(
            "Seleccione si el archivo en disco debe destruirse de inmediato al primer acceso de cualquiera o conservarse hasta que todos los destinatarios autorizados lo hayan descargado."
        ),
    )

    class Meta:
        model = EncryptedDocument
        fields = ("original_file", "description", "allowed_emails", "burn_policy")

    def clean_burn_policy(self) -> str:
        return self.cleaned_data.get("burn_policy") or EncryptedDocument.BurnPolicy.FIRST_ACCESS

    def clean_original_file(self) -> Any:
        file_obj = self.cleaned_data.get("original_file")
        if not file_obj:
            raise forms.ValidationError(_("Debe seleccionar un archivo."))
        return validate_document_file(file_obj)

    def clean_allowed_emails(self) -> List[str]:
        if hasattr(self.data, "getlist"):
            raw_entries = self.data.getlist("allowed_emails")
        else:
            raw_entries = self.cleaned_data.get("allowed_emails")
        return normalize_and_validate_email_list(raw_entries)


class EncryptedDocumentChangeForm(forms.ModelForm):
    """
    Formulario de visualización y reactivación en Django Admin.
    Permite volver a subir el archivo original para re-cifrar y reactivar el documento.
    """

    reupload_file = forms.FileField(
        label=_("Re-subir archivo original (Reactivar)"),
        required=False,
        widget=HashingFileInputWidget(),
        help_text=_(
            "Si el documento ya fue consumido o desea habilitar nuevos destinatarios, suba aquí el archivo original. Se re-cifrará y reactivará manteniendo la trazabilidad histórica."
        ),
    )
    description = forms.CharField(
        label=_("Descripción del documento"),
        required=False,
        widget=forms.Textarea(
            attrs={
                "rows": 3,
                "class": "vLargeTextField",
                "placeholder": _("Descripción informativa o motivo confidencial del trámite..."),
            }
        ),
        help_text=_(
            "Descripción que se incluirá en las notificaciones por correo y en la plantilla corporativa. Puede modificarse tanto en documentos activos como reactivados."
        ),
    )
    allowed_emails = forms.CharField(
        label=_("Correos autorizados"),
        required=True,
        widget=EmailListAdminWidget(),
        help_text=_("Destinatarios autorizados a solicitar el canje con OTP."),
    )
    burn_policy = forms.ChoiceField(
        label=_("Política de Destrucción"),
        choices=EncryptedDocument.BurnPolicy.choices,
        required=False,
        widget=forms.RadioSelect,
    )

    class Meta:
        model = EncryptedDocument
        fields = ("reupload_file", "description", "allowed_emails", "burn_policy")

    def clean_burn_policy(self) -> str:
        return self.cleaned_data.get("burn_policy") or EncryptedDocument.BurnPolicy.FIRST_ACCESS

    def clean_reupload_file(self) -> Any:
        file_obj = self.cleaned_data.get("reupload_file")
        if file_obj:
            return validate_document_file(file_obj)
        return None

    def clean_allowed_emails(self) -> List[str]:
        if hasattr(self.data, "getlist"):
            raw_entries = self.data.getlist("allowed_emails")
        else:
            raw_entries = self.cleaned_data.get("allowed_emails")
        return normalize_and_validate_email_list(raw_entries)


class DocumentAccessLogInline(admin.TabularInline):
    """Inline de auditoría legal de accesos para el panel de administración (solo lectura)."""

    model = DocumentAccessLog
    extra = 0
    can_delete = False
    readonly_fields = ("created_at", "email", "action", "ip_address", "user_agent")
    fields = ("created_at", "email", "action", "ip_address", "user_agent")

    def has_add_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False


@admin.register(EncryptedDocument)
class EncryptedDocumentAdmin(admin.ModelAdmin):
    """
    Panel de administración para la gestión, reactivación y auditoría de documentos confidenciales.
    
    Criterios de seguridad y usabilidad:
    - Cero contraseñas humanas visibles.
    - Selector dinámico de política de destrucción (primer acceso vs todos).
    - Detección proactiva de hash idéntico y reactivación sin pérdida de trazabilidad.
    - Botón de descarga de auditoría administrativa (Audit Bypass) preservando el archivo.
    - Botón de eliminación directa y soporte completo de borrado con destrucción segura física.
    """

    list_display = (
        "original_filename",
        "short_file_hash",
        "burn_policy_badge",
        "consumption_status_badge",
        "consumed_by",
        "consumed_at",
        "created_at",
        "corporate_email_button",
        "audit_download_button",
        "delete_action_button",
    )
    list_filter = ("burn_policy", "is_consumed", "created_at")
    search_fields = ("original_filename", "description", "file_hash", "consumed_by")
    inlines = [DocumentAccessLogInline]
    actions = ["admin_audit_download_action"]

    def get_list_display(self, request: HttpRequest) -> tuple:
        """Filtra columnas de acción según los permisos reales del usuario en Django."""
        fields = list(self.list_display)
        if not (request.user.is_superuser or request.user.has_perm("freedec.can_audit_download")):
            fields = [f for f in fields if f != "audit_download_button"]
        if not self.has_delete_permission(request):
            fields = [f for f in fields if f != "delete_action_button"]
        return tuple(fields)

    def get_form(self, request: HttpRequest, obj: Optional[EncryptedDocument] = None, **kwargs: Any) -> Any:
        if obj is None:
            return EncryptedDocumentAddForm
        return EncryptedDocumentChangeForm

    def get_fieldsets(self, request: HttpRequest, obj: Optional[EncryptedDocument] = None) -> Any:
        if obj is None:
            return (
                (
                    _("Registro de Documento"),
                    {
                        "fields": ("original_file", "description", "allowed_emails", "burn_policy"),
                        "description": _(
                            "Suba el documento original, configure la descripción informativa, los correos autorizados y seleccione la política de acceso (descarga única vs cuando accedan todos)."
                        ),
                    },
                ),
            )
        return (
            (
                _("Identificación del Documento"),
                {
                    "fields": (
                        "original_filename",
                        "file_hash",
                        "encrypted_file",
                        "corporate_email_template_panel",
                        "audit_download_panel",
                        "created_at",
                    ),
                },
            ),
            (
                _("Ciclo de Vida y Reactivación"),
                {
                    "fields": (
                        "reupload_file",
                        "description",
                        "burn_policy",
                        "is_consumed",
                        "consumed_by",
                        "consumed_at",
                        "consumed_recipients",
                    ),
                },
            ),
            (
                _("Destinatarios Autorizados"),
                {
                    "fields": ("allowed_emails",),
                },
            ),
        )

    def get_readonly_fields(self, request: HttpRequest, obj: Optional[EncryptedDocument] = None) -> tuple:
        if obj is None:
            return ()
        return (
            "original_filename",
            "file_hash",
            "encrypted_file",
            "corporate_email_template_panel",
            "audit_download_panel",
            "is_consumed",
            "consumed_by",
            "consumed_at",
            "consumed_recipients",
            "created_at",
        )

    def save_model(self, request: HttpRequest, obj: EncryptedDocument, form: Any, change: bool) -> None:
        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

        if not change:
            original_file = form.cleaned_data["original_file"]
            description = form.cleaned_data.get("description")
            allowed_emails = form.cleaned_data["allowed_emails"]
            burn_policy = form.cleaned_data.get("burn_policy", EncryptedDocument.BurnPolicy.FIRST_ACCESS)

            # Detectar si existe un documento activo previo con destinatarios pendientes
            file_hash = calculate_file_sha256(original_file)
            existing_doc = EncryptedDocument.objects.filter(file_hash=file_hash).first()
            omitted_pending = []
            if existing_doc and not existing_doc.is_consumed:
                consumed = set(existing_doc.consumed_recipients or [])
                pending = [e for e in (existing_doc.allowed_emails or []) if e not in consumed]
                omitted_pending = [e for e in pending if e not in allowed_emails]

            doc = upload_and_encrypt_document(
                original_file=original_file,
                allowed_emails=allowed_emails,
                burn_policy=burn_policy,
                description=description,
                reopen_existing=True,
                admin_user=request.user,
                client_ip=client_ip,
                user_agent=user_agent,
            )
            is_reactivated = getattr(doc, "_is_reactivated", False)

            obj.pk = doc.pk
            obj.id = doc.id
            obj.original_filename = doc.original_filename
            obj.description = doc.description
            obj.file_hash = doc.file_hash
            obj.encrypted_file = doc.encrypted_file
            obj.encrypted_dek = doc.encrypted_dek
            obj.allowed_emails = doc.allowed_emails
            obj.burn_policy = doc.burn_policy
            obj.consumed_recipients = doc.consumed_recipients
            obj.is_consumed = doc.is_consumed
            obj.created_at = doc.created_at
            obj._is_reactivated = is_reactivated
            obj._omitted_pending = omitted_pending
        else:
            new_description = form.cleaned_data.get("description")
            if new_description is not None:
                obj.description = new_description

            reupload_file = form.cleaned_data.get("reupload_file")
            if reupload_file:
                allowed_emails = form.cleaned_data.get("allowed_emails", obj.allowed_emails)
                burn_policy = form.cleaned_data.get("burn_policy", obj.burn_policy)

                omitted_pending = []
                if not obj.is_consumed:
                    consumed = set(obj.consumed_recipients or [])
                    pending = [e for e in (obj.allowed_emails or []) if e not in consumed]
                    omitted_pending = [e for e in pending if e not in allowed_emails]

                doc = reactivate_document(
                    document=obj,
                    original_file=reupload_file,
                    new_emails=allowed_emails,
                    burn_policy=burn_policy,
                    new_description=new_description,
                    admin_user=request.user,
                    client_ip=client_ip,
                    user_agent=user_agent,
                )
                messages.success(
                    request,
                    format_html(
                        "<strong>Documento reactivado:</strong> Se ha habilitado el acceso para {} destinatarios.",
                        len(doc.allowed_emails or []),
                    ),
                )
                if omitted_pending:
                    messages.warning(
                        request,
                        format_html(
                            "<strong>Aviso de destinatarios omitidos:</strong> Los siguientes destinatarios estaban pendientes de descargar: <strong>{}</strong>. Al no haberse incluido en la lista, no dispondrán de acceso.",
                            ", ".join(omitted_pending),
                        ),
                    )
            else:
                super().save_model(request, obj, form, change)

    def response_add(self, request: HttpRequest, obj: EncryptedDocument, post_url_continue: Optional[str] = None) -> HttpResponse:
        if getattr(obj, "_is_reactivated", False):
            messages.info(
                request,
                format_html(
                    "<strong>Documento reactivado (Identificador: {})</strong><br><br>"
                    "Se ha detectado un registro existente para este archivo y se ha actualizado en el sistema.<br>"
                    "Total de destinatarios habilitados: <strong>{}</strong>.<br>"
                    "<em>Se conserva el historial de accesos y auditoría.</em>",
                    obj.file_hash[:16],
                    len(obj.allowed_emails or []),
                ),
            )
            if getattr(obj, "_omitted_pending", None):
                messages.warning(
                    request,
                    format_html(
                        "<strong>Aviso de destinatarios omitidos:</strong> Los destinatarios pendientes de acceder: <strong>{}</strong> no fueron reincorporados a la lista.",
                        ", ".join(obj._omitted_pending),
                    ),
                )
        else:
            messages.success(
                request,
                format_html(
                    "<strong>Documento registrado correctamente.</strong><br>"
                    "Identificador SHA-256 (Localizador de descarga):<br>"
                    "<code style='background:#1e293b; color:#38bdf8; padding:4px 8px; border-radius:4px; font-weight:bold; font-size:1rem; user-select:all;'>{}</code><br><br>"
                    "<em>Facilite este identificador al destinatario para que pueda tramitar la descarga.</em>",
                    obj.file_hash,
                ),
            )
        return super().response_add(request, obj, post_url_continue)

    def delete_model(self, request: HttpRequest, obj: EncryptedDocument) -> None:
        """Tritura físicamente el archivo cifrado en disco antes de borrar de la base de datos."""
        if obj.encrypted_file:
            shred_and_delete_file(obj.encrypted_file)
        super().delete_model(request, obj)

    def delete_queryset(self, request: HttpRequest, queryset: Any) -> None:
        """Tritura físicamente los archivos cifrados en disco en eliminaciones masivas."""
        for doc in queryset:
            if doc.encrypted_file:
                shred_and_delete_file(doc.encrypted_file)
        super().delete_queryset(request, queryset)

    def has_delete_permission(self, request: HttpRequest, obj: Optional[EncryptedDocument] = None) -> bool:
        return super().has_delete_permission(request, obj)

    def get_urls(self) -> List[Any]:
        urls = super().get_urls()
        custom_urls = [
            path(
                "check-file-hash/",
                self.admin_site.admin_view(self.check_file_hash_view),
                name="freedec_encrypteddocument_check_hash",
            ),
            path(
                "<path:object_id>/audit-download/",
                self.admin_site.admin_view(self.audit_download_view),
                name="freedec_encrypteddocument_audit_download",
            ),
        ]
        return custom_urls + urls

    def check_file_hash_view(self, request: HttpRequest) -> JsonResponse:
        """Endpoint AJAX para verificar hash en cliente antes de subir."""
        file_hash = (request.GET.get("hash") or "").strip().lower()
        if not file_hash:
            return JsonResponse({"exists": False})

        doc = EncryptedDocument.objects.filter(file_hash=file_hash).first()
        if not doc:
            return JsonResponse({"exists": False})

        consumed_set = set(doc.consumed_recipients or [])
        pending = [e for e in (doc.allowed_emails or []) if e not in consumed_set]
        change_url = reverse("admin:freedec_encrypteddocument_change", args=[doc.pk])

        return JsonResponse({
            "exists": True,
            "filename": doc.original_filename,
            "description": doc.description,
            "is_consumed": doc.is_consumed,
            "pending_recipients": pending,
            "created_at": doc.created_at.strftime("%Y-%m-%d %H:%M") if doc.created_at else "",
            "change_url": change_url,
        })

    def audit_download_view(self, request: HttpRequest, object_id: str) -> HttpResponse:
        """Vista de descarga de auditoría administrativa para staff autorizado."""
        if not (request.user.is_superuser or request.user.has_perm("freedec.can_audit_download")):
            raise PermissionDenied(_("No cuenta con permisos para realizar descargas de auditoría administrativa."))

        doc = self.get_object(request, object_id)
        if not doc:
            raise Http404(_("Documento no encontrado."))

        if doc.is_consumed:
            messages.error(
                request,
                _("El documento ya fue entregado y no se encuentra disponible en la pasarela."),
            )
            return HttpResponseRedirect(reverse("admin:freedec_encrypteddocument_change", args=[object_id]))

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

        success, decrypted_bytes, original_filename, message = admin_decrypt_document(
            document=doc,
            admin_user=request.user,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        if not success:
            messages.error(request, message)
            return HttpResponseRedirect(reverse("admin:freedec_encrypteddocument_change", args=[object_id]))

        response = FileResponse(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            filename=f"AUDIT_{original_filename}",
        )
        return response

    @admin.action(description=_("Descarga de auditoría administrativa"))
    def admin_audit_download_action(self, request: HttpRequest, queryset: Any) -> Optional[HttpResponse]:
        if not (request.user.is_superuser or request.user.has_perm("freedec.can_audit_download")):
            raise PermissionDenied(_("No cuenta con permisos de auditoría."))

        count = queryset.count()
        if count != 1:
            self.message_user(
                request,
                _("Por motivos de seguridad, la descarga de auditoría debe realizarse de forma individual por documento."),
                level=messages.WARNING,
            )
            return None

        doc = queryset.first()
        download_url = reverse("admin:freedec_encrypteddocument_audit_download", args=[doc.pk])
        return HttpResponseRedirect(download_url)

    @admin.display(description=_("Hash SHA-256"))
    def short_file_hash(self, obj: EncryptedDocument) -> str:
        return f"{obj.file_hash[:12]}...{obj.file_hash[-6:]}"

    @admin.display(description=_("Política"))
    def burn_policy_badge(self, obj: EncryptedDocument) -> str:
        if obj.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
            return mark_safe(
                '<span style="background:#1e1b4b; color:#c7d2fe; border:1px solid #6366f1; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem;" title="Disponible para todos los destinatarios autorizados">Todos los destinatarios</span>'
            )
        return mark_safe(
            '<span style="background:#18181b; color:#e4e4e7; border:1px solid #71717a; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem;" title="Disponible para un único acceso (primer acceso)">Descarga única</span>'
        )

    @admin.display(description=_("Estado"))
    def consumption_status_badge(self, obj: EncryptedDocument) -> str:
        if obj.is_consumed:
            return format_html(
                '<span style="background:#450a0a; color:#f87171; border:1px solid #ef4444; padding:3px 10px; border-radius:12px; font-weight:bold; font-size:0.8rem;" title="Retirado el {}">Retirado ({})</span>',
                obj.consumed_at.strftime("%Y-%m-%d %H:%M UTC") if obj.consumed_at else "",
                obj.consumed_by or _("desconocido"),
            )
        if obj.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
            total = len(obj.allowed_emails or [])
            consumed = len(obj.consumed_recipients or [])
            return format_html(
                '<span style="background:#082f49; color:#38bdf8; border:1px solid #0284c7; padding:3px 10px; border-radius:12px; font-weight:bold; font-size:0.8rem;" title="Descargado por {consumed}/{total} destinatarios">Disponible ({consumed}/{total} descargados)</span>',
                consumed=consumed,
                total=total,
            )
        return mark_safe(
            '<span style="background:#022c22; color:#34d399; border:1px solid #10b981; padding:3px 10px; border-radius:12px; font-weight:bold; font-size:0.8rem;">Disponible para descarga</span>'
        )

    @admin.display(description=_("Plantilla Correo"))
    def corporate_email_button(self, obj: EncryptedDocument) -> str:
        """Botón interactivo en la lista para copiar el texto de notificación con hash y nombre de archivo."""
        text = generate_corporate_email_text(obj)
        escaped_json = json.dumps(text)
        return format_html(
            '<button type="button" class="button" style="background:#0f766e; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:0.8rem; cursor:pointer; border:none; display:inline-flex; align-items:center; gap:4px;" '
            'onclick=\'navigator.clipboard.writeText({text_json}).then(() => {{ const orig = this.innerHTML; this.innerHTML="¡Copiado!"; this.style.background="#059669"; setTimeout(() => {{ this.innerHTML=orig; this.style.background="#0f766e"; }}, 2500); }}).catch(() => prompt("Copie el texto para el correo:", {text_json}));\' '
            'title="Copiar plantilla de notificación para enviar por correo al destinatario">'
            'Plantilla'
            '</button>',
            text_json=escaped_json,
        )

    @admin.display(description=_("Auditoría"))
    def audit_download_button(self, obj: EncryptedDocument) -> str:
        """Botón interactivo en la lista de documentos para descarga de auditoría."""
        if obj.is_consumed:
            return format_html(
                '<span style="background:#7f1d1d; color:#fca5a5; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:0.8rem;">Retirado</span>'
            )
        download_url = reverse("admin:freedec_encrypteddocument_audit_download", args=[obj.pk])
        return format_html(
            '<a href="{}" class="button" style="background:#0284c7; color:#fff; padding:3px 8px; border-radius:4px; text-decoration:none; font-weight:bold; font-size:0.8rem;" title="Descarga de auditoría administrativa">'
            'Auditoría'
            '</a>',
            download_url,
        )

    @admin.display(description=_("Eliminar"))
    def delete_action_button(self, obj: EncryptedDocument) -> str:
        """Botón directo de eliminación de documento."""
        url = reverse("admin:freedec_encrypteddocument_delete", args=[obj.pk])
        return format_html(
            '<a class="button" href="{}" style="background-color: #ba2121; color: white; padding: 4px 10px; border-radius: 4px; text-decoration: none; font-size: 0.8rem; font-weight: bold;" title="Eliminar documento">🗑️</a>',
            url,
        )

    def corporate_email_template_panel(self, obj: EncryptedDocument) -> str:
        """Panel con texto formal prediseñado listo para copiar o abrir en cliente de correo."""
        text = generate_corporate_email_text(obj)
        escaped_json = json.dumps(text)
        destinatarios = ", ".join(obj.allowed_emails or [])
        mailto_subject = quote(f"Documento disponible para su descarga: {obj.original_filename}")
        mailto_body = quote(text)
        mailto_link = f"mailto:{destinatarios}?subject={mailto_subject}&body={mailto_body}"

        return format_html(
            '<div style="background:#0f172a; border:1px solid #334155; padding:14px; border-radius:8px; margin-bottom:15px; color:#e2e8f0;">'
            '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; flex-wrap:wrap; gap:8px;">'
            '<strong style="color:#38bdf8; font-size:0.95rem;">Plantilla de Notificación por Correo Electrónico:</strong>'
            '<div style="display:flex; gap:8px;">'
            '<button type="button" class="button" style="background:#0284c7; color:#fff; padding:5px 12px; border-radius:4px; font-weight:bold; font-size:0.82rem; cursor:pointer; border:none;" '
            'onclick=\'navigator.clipboard.writeText({text_json}).then(() => {{ const orig = this.innerHTML; this.innerHTML="¡Texto copiado!"; this.style.background="#059669"; setTimeout(() => {{ this.innerHTML=orig; this.style.background="#0284c7"; }}, 2500); }}).catch(() => prompt("Copie el texto para el correo:", {text_json}));\'>'
            'Copiar texto'
            '</button>'
            '<a href="{mailto_link}" class="button" style="background:#475569; color:#fff; padding:5px 12px; border-radius:4px; font-weight:bold; font-size:0.82rem; text-decoration:none; display:inline-block;" title="Abrir en cliente de correo local">'
            'Abrir en cliente de correo'
            '</a>'
            '</div>'
            '</div>'
            '<div style="font-size:0.82rem; color:#94a3b8; margin-bottom:8px;">'
            'Utilice este texto formal para notificar a los destinatarios. Incluye el identificador (SHA-256), nombre del archivo, descripción e instrucciones de descarga.'
            '</div>'
            '<textarea readonly rows="9" style="width:100%; box-sizing:border-box; background:#1e293b; color:#f1f5f9; border:1px solid #475569; border-radius:6px; font-family:monospace; font-size:0.85rem; padding:10px; line-height:1.45; resize:vertical;" id="corporate_email_textarea">{text}</textarea>'
            '</div>',
            text=text,
            text_json=escaped_json,
            mailto_link=mailto_link,
        )

    def audit_download_panel(self, obj: EncryptedDocument) -> str:
        """Panel de herramientas de auditoría en la vista detallada del documento."""
        if obj.is_consumed:
            return format_html(
                '<div style="background:#450a0a; border:1px solid #dc2626; color:#fecaca; padding:10px; border-radius:6px;">'
                '<strong>Documento ya entregado:</strong> '
                'El documento ya ha sido retirado de la pasarela y no se encuentra disponible para descargas de auditoría.'
                '</div>'
            )
        download_url = reverse("admin:freedec_encrypteddocument_audit_download", args=[obj.pk])
        return format_html(
            '<div style="background:#082f49; border:1px solid #0284c7; padding:12px; border-radius:6px; color:#e0f2fe;">'
            '<strong style="color:#38bdf8;">Descarga de Auditoría Administrativa:</strong><br>'
            '<span style="font-size:0.85rem; color:#bae6fd;">Permite al personal autorizado inspeccionar el archivo original descifrado sin afectar a la disponibilidad para los destinatarios.</span><br><br>'
            '<a href="{}" class="button" style="background:#0284c7; color:#fff; padding:6px 14px; border-radius:4px; font-weight:bold; text-decoration:none; display:inline-block;">'
            'Descargar copia de auditoría'
            '</a>'
            '</div>',
            download_url,
        )


@admin.register(AccessVerificationToken)
class AccessVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ("created_at", "email", "document", "is_used", "failed_attempts", "expires_at")
    list_filter = ("is_used", "created_at")
    search_fields = ("email", "document__file_hash", "document__original_filename")
    readonly_fields = ("document", "email", "otp_code", "created_at", "expires_at", "is_used", "failed_attempts")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return super().has_delete_permission(request, obj)


@admin.register(DocumentAccessLog)
class DocumentAccessLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "email", "action", "document", "ip_address")
    list_filter = ("action", "created_at")
    search_fields = ("email", "ip_address", "document__file_hash", "document__original_filename")
    readonly_fields = ("document", "email", "action", "ip_address", "user_agent", "created_at")

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return super().has_delete_permission(request, obj)
