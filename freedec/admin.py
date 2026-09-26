from django import forms
from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

from freedec.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from freedec.services import DocumentManagementService, calculate_file_sha256
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

    def value_from_datadict(self, data, files, name):
        if hasattr(data, "getlist"):
            return data.getlist(name)
        val = data.get(name)
        return [val] if val else []


class HashingFileInputWidget(forms.ClearableFileInput):
    """
    Widget de subida con detección automática instantánea del hash SHA-256 en el cliente.
    Si el archivo ya existe en el sistema, muestra un aviso inmediato con enlace para abrirlo directamente
    y advierte si existen destinatarios pendientes de acceder.
    """

    def render(self, name, value, attrs=None, renderer=None):
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
    Formulario de alta para Django Admin:
    El admin sube el archivo original, los correos autorizados y la política de destrucción.
    El sistema aplica el cifrado DEK multi-usuario y sobres individuales (user_envelopes).
    """

    original_file = forms.FileField(
        label=_("Archivo Documental Original"),
        widget=HashingFileInputWidget(),
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
        fields = ("original_file", "allowed_emails", "burn_policy")

    def clean_burn_policy(self):
        val = self.cleaned_data.get("burn_policy")
        return val or EncryptedDocument.BurnPolicy.FIRST_ACCESS

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
    reupload_file = forms.FileField(
        label=_("Re-subir archivo original (Reactivar)"),
        required=False,
        widget=forms.FileInput(),
        help_text=_(
            "Si el documento ya fue consumido o desea re-armarlo para nuevos destinatarios, suba aquí el archivo original con el mismo hash."
        ),
    )

    class Meta:
        model = EncryptedDocument
        fields = ("allowed_emails", "reupload_file")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and not self.instance.is_consumed:
            consumed = set(self.instance.consumed_recipients or [])
            pending = [e for e in (self.instance.allowed_emails or []) if e not in consumed]
            if pending:
                pending_str = ", ".join(f"'{p}'" for p in pending)
                warning_notice = format_html(
                    "<div style='background:#451a03; border:2px solid #f59e0b; padding:10px 14px; border-radius:6px; color:#fef3c7; margin-bottom:10px;'>"
                    "<strong style='color:#fbbf24; font-size:0.92rem;'>⚠️ ¡ATENCIÓN! Este documento aún no ha finalizado:</strong><br>"
                    "Destinatarios pendientes de acceder: <strong>{}</strong>.<br>"
                    "<span style='font-size:0.85rem;'>Si re-sube el archivo original para reactivarlo, los anteriores perderán el acceso a menos que los vuelva a incluir arriba en <em>Correos Autorizados</em>.</span>"
                    "</div>",
                    pending_str,
                )
                self.fields["reupload_file"].help_text = mark_safe(
                    warning_notice + str(self.fields["reupload_file"].help_text)
                )

    def clean_allowed_emails(self):
        if hasattr(self.data, "getlist"):
            raw_entries = self.data.getlist("allowed_emails")
        else:
            raw_val = self.cleaned_data.get("allowed_emails") or self.data.get("allowed_emails") or ""
            raw_entries = [raw_val] if isinstance(raw_val, str) else list(raw_val)

        return normalize_and_validate_email_list(raw_entries)

    def clean_reupload_file(self):
        file_obj = self.cleaned_data.get("reupload_file")
        if file_obj:
            validate_document_file(file_obj)
            new_hash = calculate_file_sha256(file_obj)
            if self.instance and self.instance.file_hash and new_hash != self.instance.file_hash:
                raise forms.ValidationError(
                    _(
                        "El archivo no coincide con el hash del documento original (esperado: %(expected)s, obtenido: %(obtained)s)."
                    )
                    % {"expected": self.instance.file_hash[:12] + "...", "obtained": new_hash[:12] + "..."}
                )
        return file_obj


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
            "descifrado_parcial_preservado": ("#3b82f6", "#172554"),
            "reactivacion_documento": ("#14b8a6", "#042f2e"),
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
        "burn_policy_badge",
        "consumption_status_badge",
        "access_count",
        "last_accessed_at",
        "download_link",
        "admin_download_button",
        "delete_action_button",
    )
    list_filter = ("burn_policy", "is_consumed", "created_at", "last_accessed_at")
    search_fields = ("original_filename", "file_hash", "consumed_by", "last_accessed_by")

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "check-file-hash/",
                self.admin_site.admin_view(self.check_file_hash),
                name="freedec_encrypteddocument_check_hash",
            ),
            path(
                "<path:object_id>/admin-download/",
                self.admin_site.admin_view(self.admin_download),
                name="freedec_encrypteddocument_admin_download",
            ),
        ]
        return custom_urls + urls

    def check_file_hash(self, request):
        """Endpoint JSON para verificar en tiempo real si un hash ya existe en la base de datos."""
        file_hash = request.GET.get("hash", "").strip().lower()
        if not file_hash:
            return JsonResponse({"exists": False})
        doc = EncryptedDocument.objects.filter(file_hash=file_hash).order_by("-created_at").first()
        if not doc:
            return JsonResponse({"exists": False})

        pending_recipients = []
        if not doc.is_consumed:
            consumed = set(doc.consumed_recipients or [])
            pending_recipients = [e for e in (doc.allowed_emails or []) if e not in consumed]

        return JsonResponse({
            "exists": True,
            "id": doc.pk,
            "filename": doc.original_filename,
            "is_consumed": doc.is_consumed,
            "burn_policy": doc.burn_policy,
            "pending_recipients": pending_recipients,
            "consumed_recipients": doc.consumed_recipients or [],
            "change_url": reverse("admin:freedec_encrypteddocument_change", args=[doc.pk]),
            "allowed_emails": doc.allowed_emails,
            "created_at": doc.created_at.strftime("%Y-%m-%d %H:%M"),
        })

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
                        "fields": ("original_file", "allowed_emails", "burn_policy"),
                        "description": _(
                            "Suba el archivo original, especifique los correos autorizados y seleccione la política de destrucción (primer acceso vs cuando accedan todos)."
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
                    "fields": ("encrypted_file", "admin_tools_panel", "reupload_file"),
                    "description": _(
                        "El archivo binario se almacena en disco cifrado con la DEK. Puede descargar una copia administrativa o re-subir el archivo original para reactivarlo."
                    ),
                },
            ),
            (
                _("Ciclo de Vida y Destrucción (Burn-After-Read)"),
                {
                    "fields": ("burn_policy", "is_consumed", "consumed_by", "consumed_at", "consumed_recipients"),
                    "description": _(
                        "Control del ciclo de vida y política de destrucción: determina si el documento se borra tras el primer acceso o tras el acceso de todos."
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
            "burn_policy",
            "is_consumed",
            "consumed_by",
            "consumed_at",
            "consumed_recipients",
            "access_count",
            "last_accessed_at",
            "last_accessed_by",
            "created_at",
            "updated_at",
        )

    def save_model(self, request, obj, form, change):
        service = DocumentManagementService()
        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

        if not change:
            original_file = form.cleaned_data["original_file"]
            allowed_emails = form.cleaned_data["allowed_emails"]
            burn_policy = form.cleaned_data.get("burn_policy", EncryptedDocument.BurnPolicy.FIRST_ACCESS)

            # Detectar si existe un documento activo previo con destinatarios pendientes
            file_hash = calculate_file_sha256(original_file)
            existing_doc = EncryptedDocument.objects.filter(file_hash=file_hash).order_by("-created_at").first()
            omitted_pending = []
            if existing_doc and not existing_doc.is_consumed:
                consumed = set(existing_doc.consumed_recipients or [])
                pending = [e for e in (existing_doc.allowed_emails or []) if e not in consumed]
                omitted_pending = [e for e in pending if e not in allowed_emails]

            doc, is_reactivated = service.upload_and_encrypt_document(
                original_file=original_file,
                allowed_emails=allowed_emails,
                burn_policy=burn_policy,
                reopen_existing=True,
                admin_user=request.user,
                client_ip=client_ip,
                user_agent=user_agent,
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
            obj.burn_policy = doc.burn_policy
            obj.consumed_recipients = doc.consumed_recipients
            obj.is_consumed = doc.is_consumed
            obj.created_at = doc.created_at
            obj.updated_at = doc.updated_at
            obj._is_reactivated = is_reactivated
            obj._omitted_pending = omitted_pending
        else:
            reupload_file = form.cleaned_data.get("reupload_file")
            if reupload_file:
                allowed_emails = form.cleaned_data.get("allowed_emails", obj.allowed_emails)
                omitted_pending = []
                if not obj.is_consumed:
                    consumed = set(obj.consumed_recipients or [])
                    pending = [e for e in (obj.allowed_emails or []) if e not in consumed]
                    omitted_pending = [e for e in pending if e not in allowed_emails]

                doc = service.reactivate_document(
                    document=obj,
                    original_file=reupload_file,
                    new_emails=allowed_emails,
                    admin_user=request.user,
                    client_ip=client_ip,
                    user_agent=user_agent,
                )
                messages.success(
                    request,
                    format_html(
                        "<strong>♻️ Documento reactivado con éxito:</strong> Se ha re-cifrado el archivo en disco y habilitado para {} destinatarios.",
                        len(doc.allowed_emails or []),
                    ),
                )
                if omitted_pending:
                    messages.warning(
                        request,
                        format_html(
                            "⚠️ <strong>Aviso de destinatarios omitidos:</strong> Este documento aún no había finalizado y los siguientes destinatarios estaban pendientes de acceder: <strong>{}</strong>. Al no haberse vuelto a añadir a la lista, han perdido el acceso.",
                            ", ".join(omitted_pending),
                        ),
                    )
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

        if getattr(obj, "_is_reactivated", False):
            messages.info(
                request,
                format_html(
                    "<strong>♻️ REGISTRO HISTÓRICO EXISTENTE LOCALIZADO Y REACTIVADO (Hash: {})</strong><br><br>"
                    "{}"
                    "Se ha detectado el registro existente para este archivo. Se ha re-cifrado y reactivado en el sistema.<br>"
                    "Total destinatarios habilitados: <strong>{}</strong> (reemplazando los anteriores, que se preservan en el histórico).<br>"
                    "<em>Todo el historial previo de descargas y auditoría se mantiene preservado intacto.</em>",
                    obj.file_hash[:16],
                    download_html,
                    len(obj.allowed_emails or []),
                ),
            )
            if getattr(obj, "_omitted_pending", None):
                messages.warning(
                    request,
                    format_html(
                        "⚠️ <strong>Aviso de destinatarios omitidos:</strong> Este documento aún no había finalizado y los siguientes destinatarios estaban pendientes de acceder: <strong>{}</strong>. Al no haberse vuelto a añadir a la lista, han perdido el acceso.",
                        ", ".join(obj._omitted_pending),
                    ),
                )
            return HttpResponseRedirect(
                reverse("admin:freedec_encrypteddocument_change", args=[obj.pk])
            )

        policy_notice = (
            "Se destruirá físicamente en cuanto el PRIMER destinatario descargue su copia (Burn-after-first-read)."
            if obj.burn_policy == EncryptedDocument.BurnPolicy.FIRST_ACCESS
            else "Se conservará en disco hasta que TODOS los destinatarios autorizados hayan descargado su copia."
        )

        messages.success(
            request,
            format_html(
                "<strong>✅ Documento '{}' cifrado y registrado exitosamente (SHA-256: {})</strong><br><br>"
                "{}"
                "<strong>🔐 ARQUITECTURA ZERO-TRUST (Magic Link / OTP):</strong><br>"
                "Se han generado sobres digitales individuales para {} destinatarios autorizados.<br>"
                "Cuando los destinatarios soliciten el acceso en el portal público, recibirán un enlace seguro y un código OTP temporal válido por 15 minutos.<br>"
                "<strong>⚠️ Política de destrucción:</strong> <em>{}</em>",
                obj.original_filename,
                obj.file_hash,
                download_html,
                len(obj.allowed_emails or []),
                policy_notice,
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

    @admin.display(description=_("Política"))
    def burn_policy_badge(self, obj):
        if obj.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
            return mark_safe(
                '<span style="background:#1e1b4b; color:#c7d2fe; border:1px solid #6366f1; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem;" title="Destrucción solo cuando todos los destinatarios hayan accedido">👥 Todos</span>'
            )
        return mark_safe(
            '<span style="background:#18181b; color:#e4e4e7; border:1px solid #71717a; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem;" title="Destrucción inmediata al primer acceso">⚡ 1er Acceso</span>'
        )

    @admin.display(description=_("Estado"))
    def consumption_status_badge(self, obj):
        if obj.is_consumed:
            return format_html(
                '<span style="background:#450a0a; color:#f87171; border:1px solid #ef4444; padding:3px 10px; border-radius:12px; font-weight:bold; font-size:0.8rem;" title="Retirado el {}">🔥 Consumido ({})</span>',
                obj.consumed_at.strftime("%Y-%m-%d %H:%M UTC") if obj.consumed_at else "",
                obj.consumed_by or _("desconocido"),
            )
        if obj.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
            total = len(obj.allowed_emails or [])
            consumed = len(obj.consumed_recipients or [])
            return format_html(
                '<span style="background:#082f49; color:#38bdf8; border:1px solid #0284c7; padding:3px 10px; border-radius:12px; font-weight:bold; font-size:0.8rem;" title="Descargado por {}/{} destinatarios">👥 Activo ({}/{} accedidos)</span>',
                consumed,
                total,
                consumed,
                total,
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
                '<div style="background:#450a0a; border:1px solid #ef4444; padding:14px; border-radius:8px; color:#fca5a5;">'
                '<strong>🔥 DOCUMENTO CONSUMIDO Y DESTRUIDO:</strong><br>'
                'Este documento fue descargado por <strong>{}</strong> el <strong>{}</strong>.<br>'
                'El archivo físico ha sido eliminado del almacenamiento de forma permanente por la política Burn-After-Read.<br>'
                '<div style="margin-top:10px; padding:8px 12px; background:#2a0808; border-radius:6px; font-size:0.85rem; color:#fecaca;">'
                '💡 <strong>¿Desea volver a subirlo y habilitarlo a más destinatarios?</strong><br>'
                'Suba de nuevo el archivo original en el campo <em>"Re-subir archivo original (Reactivar)"</em> en este formulario o desde el formulario de nuevo documento. Se re-cifrará el archivo, se activarán las descargas y se mantendrá todo el registro histórico anterior intacto.'
                '</div>'
                '</div>',
                obj.consumed_by or "desconocido",
                obj.consumed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if obj.consumed_at else "",
            )

        policy_info = ""
        if obj.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
            total = len(obj.allowed_emails or [])
            consumed = len(obj.consumed_recipients or [])
            policy_info = format_html(
                '<div style="margin-top:6px; font-size:0.8rem; color:#93c5fd;">'
                '👥 <strong>Política:</strong> Cuando accedan todos (Descargado por {}/{} destinatarios). '
                'Descargas completadas: {}'
                '</div>',
                consumed,
                total,
                ", ".join(obj.consumed_recipients) if obj.consumed_recipients else _("ninguna todavía"),
            )

        url = reverse("admin:freedec_encrypteddocument_admin_download", args=[obj.pk])
        return format_html(
            '<div style="background:#1e1b4b; border:1px solid #6366f1; padding:12px; border-radius:8px; display:flex; justify-content:space-between; align-items:center;">'
            '<div>'
            '<strong style="color:#c7d2fe;">🔓 Descarga Administrativa Preservada (Audit Bypass):</strong><br>'
            '<span style="color:#94a3b8; font-size:0.85rem;">Descarga el archivo original descifrado. NO se destruirá el binario ni se marcará como consumido.</span>'
            '{}'
            '</div>'
            '<a href="{}" class="button" style="background:#6366f1; color:white; padding:8px 16px; border-radius:6px; font-weight:bold; text-decoration:none;">'
            '🔓 Descargar Original'
            '</a>'
            '</div>',
            policy_info,
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
