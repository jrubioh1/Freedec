from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.shortcuts import render
from django.views import View

from freedec.forms import (
    AdminDocumentUploadForm,
    PublicDecryptDocumentForm,
    PublicPasswordRequestForm,
)
from freedec.services import DocumentManagementService


class AdminUploadGuiView(LoginRequiredMixin, View):
    """
    Vista Web GUI protegida para que administradores autenticados suban y cifren documentos.
    Requiere inicio de sesión (LoginRequiredMixin).
    """

    template_name = "freedec/admin_upload.html"

    def get(self, request):
        form = AdminDocumentUploadForm()
        return render(request, self.template_name, {
            "form": form,
            "submitted_emails": [""],
        })

    def post(self, request):
        form = AdminDocumentUploadForm(request.POST, request.FILES)
        submitted_emails = request.POST.getlist("allowed_emails")
        if not submitted_emails:
            single_val = request.POST.get("allowed_emails", "")
            submitted_emails = [single_val] if single_val else [""]

        if not form.is_valid():
            return render(
                request,
                self.template_name,
                {"form": form, "submitted_emails": submitted_emails},
                status=400,
            )

        original_file = form.cleaned_data["original_file"]
        plain_password = form.cleaned_data["plain_password"]
        allowed_emails = form.cleaned_data["allowed_emails"]

        service = DocumentManagementService()

        try:
            document, raw_access_code = service.upload_and_encrypt_document(
                original_file=original_file,
                plain_password=plain_password,
                allowed_emails=allowed_emails,
            )
        except ValidationError as exc:
            form.add_error(None, str(exc.message if hasattr(exc, "message") else exc))
            return render(
                request,
                self.template_name,
                {"form": form, "submitted_emails": submitted_emails},
                status=400,
            )
        except Exception as exc:
            form.add_error(None, f"Error interno en el procesamiento: {exc}")
            return render(
                request,
                self.template_name,
                {"form": form, "submitted_emails": submitted_emails},
                status=500,
            )

        encrypted_url = None
        if document.encrypted_file:
            encrypted_url = request.build_absolute_uri(document.encrypted_file.url)

        import urllib.parse
        txt_filename = f"{document.original_filename}_credenciales.txt"
        creds_text = (
            "================================================================================\n"
            "FREEDEC - CREDENCIALES DE RECUPERACIÓN Y CONTROL DE DOCUMENTO\n"
            "================================================================================\n\n"
            f"DOCUMENTO ORIGINAL:  {document.original_filename}\n"
            f"ARCHIVO CIFRADO:     {document.original_filename}.enc\n"
            f"HASH SHA-256:        {document.file_hash}\n"
            f"FECHA DE REGISTRO:   {document.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if document.created_at else ''}\n\n"
            "--------------------------------------------------------------------------------\n"
            "1. CÓDIGO SECRETO DE ACCESO (ZERO-KNOWLEDGE):\n"
            "--------------------------------------------------------------------------------\n"
            f"{raw_access_code}\n\n"
            "* Entregue este código al destinatario por canal seguro (Signal, SMS o en persona).\n\n"
            "--------------------------------------------------------------------------------\n"
            "2. CONTRASEÑA O CLAVE DE DESCIFRADO:\n"
            "--------------------------------------------------------------------------------\n"
            f"{getattr(document, 'generated_password', plain_password) or ''}\n\n"
            "* Esta clave descifra el archivo .enc y permite recuperar el archivo original.\n\n"
            "--------------------------------------------------------------------------------\n"
            "3. DESTINATARIOS AUTORIZADOS:\n"
            "--------------------------------------------------------------------------------\n"
            + "\n".join(f"- {e}" for e in (document.allowed_emails or [])) + "\n\n"
            "--------------------------------------------------------------------------------\n"
            "4. PORTALES DE ACCESO:\n"
            "--------------------------------------------------------------------------------\n"
            "- Solicitar Contraseña:  http://127.0.0.1:8000/\n"
            "- Descifrar Archivo:     http://127.0.0.1:8000/descifrar/\n"
            "================================================================================\n"
        )
        txt_data_uri = f"data:text/plain;charset=utf-8,{urllib.parse.quote(creds_text)}"

        context = {
            "success": True,
            "document": document,
            "raw_access_code": raw_access_code,
            "raw_password": getattr(document, "generated_password", plain_password),
            "encrypted_file_url": encrypted_url,
            "txt_data_uri": txt_data_uri,
            "txt_filename": txt_filename,
        }
        return render(request, self.template_name, context, status=201)


def get_client_ip(request):
    """Obtiene la IP remota del cliente considerando cabeceras de proxy inverso."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


class PublicRequestGuiView(View):
    """
    Vista Web GUI pública para que los destinatarios suban su copia del archivo,
    ingresen su access_code y su correo electrónico para recibir la clave descifrada.
    """

    template_name = "freedec/public_request.html"

    def get(self, request):
        form = PublicPasswordRequestForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = PublicPasswordRequestForm(request.POST, request.FILES)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form}, status=400)

        uploaded_file = form.cleaned_data["file"]
        access_code = form.cleaned_data["access_code"]
        email = form.cleaned_data["email"]

        service = DocumentManagementService()
        success, message = service.verify_and_dispatch_password(
            uploaded_file=uploaded_file,
            access_code=access_code,
            recipient_email=email,
            client_ip=get_client_ip(request),
        )

        context = {
            "form": PublicPasswordRequestForm(),  # Reset form
            "result_message": message,
            "is_success": success,
        }
        return render(request, self.template_name, context, status=200 if success else 500)


class PublicDecryptGuiView(View):
    """
    Vista Web GUI pública para que los destinatarios descifren y descarguen el documento original
    subiendo el archivo .enc y proporcionando la contraseña recibida por correo.
    """

    template_name = "freedec/public_decrypt.html"

    def get(self, request):
        form = PublicDecryptDocumentForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        form = PublicDecryptDocumentForm(request.POST, request.FILES)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form}, status=400)

        uploaded_file = form.cleaned_data["file"]
        password = form.cleaned_data["password"]

        service = DocumentManagementService()
        success, decrypted_bytes, suggested_filename, mimetype, message = (
            service.decrypt_document_with_password(
                encrypted_file_obj=uploaded_file,
                password=password,
                client_ip=get_client_ip(request),
            )
        )

        if not success:
            return render(
                request,
                self.template_name,
                {"form": form, "error_message": message},
                status=400,
            )

        # Entrega de descarga segura con tipo MIME adecuado y Content-Disposition
        response = HttpResponse(decrypted_bytes, content_type=mimetype or "application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{suggested_filename}"'
        return response
