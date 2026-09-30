import hashlib
import io
import os
import shutil
import tempfile
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from freedec.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from freedec.services import request_document_access, upload_and_encrypt_document

User = get_user_model()
TEST_FERNET_KEY = Fernet.generate_key().decode()

MINIMAL_TEST_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


@override_settings(FREEDEC_FERNET_KEY=TEST_FERNET_KEY)
class FreedecViewsSecurityTestCase(TestCase):
    """
    Pruebas funcionales y de seguridad de controladores, vistas web GUI, API REST y Django Admin.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._temp_media = tempfile.mkdtemp()
        cls._media_override = override_settings(MEDIA_ROOT=cls._temp_media)
        cls._media_override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._media_override.disable()
        shutil.rmtree(cls._temp_media, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.client = Client()
        self.test_content = MINIMAL_TEST_PDF
        self.expected_sha256 = hashlib.sha256(self.test_content).hexdigest().lower()
        self.allowed_email = "titular@empresa.com"

        self.superuser = User.objects.create_superuser(
            username="admin_super",
            email="admin@freedec.local",
            password="AdminPassword#2026",
        )
        self.staff_user = User.objects.create_user(
            username="staff_auditor",
            email="auditor@freedec.local",
            password="StaffPassword#2026",
            is_staff=True,
        )

        upload_file = SimpleUploadedFile("expediente_confidencial.pdf", self.test_content)
        self.document = upload_and_encrypt_document(
            original_file=upload_file,
            allowed_emails=[self.allowed_email],
        )

    # --------------------------------------------------------------------------
    # 1. VISTA DE SOLICITUD (RequestAccessView - /freedec/solicitar/)
    # --------------------------------------------------------------------------
    def test_request_access_view_get_empty_and_prefilled(self):
        """GET /freedec/solicitar/ permite pre-rellenar ?hash=... por URL."""
        # 1. Sin parámetros
        resp1 = self.client.get(reverse("freedec:request-access"))
        self.assertEqual(resp1.status_code, 200)
        self.assertContains(resp1, "Hash SHA-256")
        self.assertNotContains(resp1, 'type="file"')  # Regla 1: Cero transporte de binario

        # 2. Con ?hash=
        resp2 = self.client.get(f"{reverse('freedec:request-access')}?hash={self.document.file_hash}")
        self.assertEqual(resp2.status_code, 200)
        self.assertContains(resp2, self.document.file_hash)

    def test_request_access_view_post_valid_redirects_and_sets_session(self):
        """POST con hash y correo autorizados almacena en sesión y redirige a canjear."""
        post_data = {
            "file_hash": self.document.file_hash,
            "email": self.allowed_email,
        }
        resp = self.client.post(reverse("freedec:request-access"), post_data)
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("freedec:redeem-otp"), resp.url)

        # Comprobar sesión
        session = self.client.session
        self.assertEqual(session.get("freedec_file_hash"), self.document.file_hash)
        self.assertEqual(session.get("freedec_email"), self.allowed_email)

    def test_request_access_view_post_invalid_hash(self):
        """POST con formato de hash inválido debe retornar 400 Bad Request."""
        post_data = {
            "file_hash": "z" * 64,
            "email": self.allowed_email,
        }
        resp = self.client.post(reverse("freedec:request-access"), post_data)
        self.assertEqual(resp.status_code, 400)
        self.assertContains(resp, "64 caracteres hexadecimales", status_code=400)

    # --------------------------------------------------------------------------
    # 2. VISTA DE CANJE (RedeemOtpView - /freedec/canjear/)
    # --------------------------------------------------------------------------
    def test_redeem_otp_view_get_without_context_redirects(self):
        """Si el usuario entra a /canjear/ sin hash ni sesión, se le redirige a /solicitar/."""
        resp = self.client.get(reverse("freedec:redeem-otp"))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse("freedec:request-access"), resp.url)

    def test_redeem_otp_view_post_success_burn_after_read(self):
        """
        Canje exitoso con OTP válido:
        - Devuelve FileResponse con los bytes descifrados (as_attachment=True).
        - El archivo en disco es destruido (Burn-After-Read).
        """
        # Generar OTP solicitando acceso previamente
        request_document_access(self.document.file_hash, self.allowed_email)
        token = AccessVerificationToken.objects.get(document=self.document, email=self.allowed_email)

        physical_path = self.document.encrypted_file.path
        self.assertTrue(os.path.exists(physical_path))

        post_data = {
            "file_hash": self.document.file_hash,
            "email": self.allowed_email,
            "otp_code": token.otp_code,
        }
        resp = self.client.post(reverse("freedec:redeem-otp"), post_data)
        self.assertEqual(resp.status_code, 200)

        # Comprobar FileResponse y cabeceras de descarga
        self.assertEqual(resp["Content-Disposition"], 'attachment; filename="expediente_confidencial.pdf"')
        content = b"".join(resp.streaming_content) if resp.streaming else resp.content
        self.assertEqual(content, self.test_content)

        # Verificar destrucción física en disco
        self.assertFalse(os.path.exists(physical_path))

        # Registro en BD marcado como consumido
        self.document.refresh_from_db()
        self.assertTrue(self.document.is_consumed)
        self.assertEqual(self.document.consumed_by, self.allowed_email)

    def test_redeem_otp_view_post_wrong_otp(self):
        """Código OTP incorrecto devuelve 400 y mensaje de error con intentos."""
        request_document_access(self.document.file_hash, self.allowed_email)

        post_data = {
            "file_hash": self.document.file_hash,
            "email": self.allowed_email,
            "otp_code": "000000",
        }
        resp = self.client.post(reverse("freedec:redeem-otp"), post_data)
        self.assertEqual(resp.status_code, 400)
        self.assertContains(resp, "Código de verificación incorrecto", status_code=400)

    # --------------------------------------------------------------------------
    # 3. PANEL DE ADMINISTRACIÓN (freedec/admin.py)
    # --------------------------------------------------------------------------
    def test_admin_change_form_no_password_fields(self):
        """El panel de administración no debe exhibir ningún campo de contraseña."""
        self.client.force_login(self.superuser)
        url = reverse("admin:freedec_encrypteddocument_change", args=[self.document.pk])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, 'name="password"')
        self.assertNotContains(resp, 'name="access_code"')
        self.assertNotContains(resp, 'name="encrypted_password"')

    def test_admin_audit_download_permission_denied_for_unauthorized_staff(self):
        """Un usuario staff sin permiso específico no puede realizar descargas de auditoría."""
        self.client.force_login(self.staff_user)
        audit_url = reverse("admin:freedec_encrypteddocument_audit_download", args=[self.document.pk])
        resp = self.client.get(audit_url)
        self.assertEqual(resp.status_code, 403)

    def test_admin_audit_download_success_for_authorized_staff(self):
        """El staff con permiso can_audit_download descarga la copia sin destruir el documento."""
        perm = Permission.objects.get(codename="can_audit_download")
        self.staff_user.user_permissions.add(perm)
        self.client.force_login(self.staff_user)

        physical_path = self.document.encrypted_file.path
        audit_url = reverse("admin:freedec_encrypteddocument_audit_download", args=[self.document.pk])
        resp = self.client.get(audit_url)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("AUDIT_", resp["Content-Disposition"])
        content = b"".join(resp.streaming_content) if resp.streaming else resp.content
        self.assertEqual(content, self.test_content)

        # El archivo en disco NO debe haber sido destruido
        self.assertTrue(os.path.exists(physical_path))
        self.document.refresh_from_db()
        self.assertFalse(self.document.is_consumed)

        # Auditoría registrada
        self.assertTrue(
            DocumentAccessLog.objects.filter(
                document=self.document,
                action=DocumentAccessLog.Action.ADMIN_DESCARGA_PRESERVADA,
            ).exists()
        )

    # --------------------------------------------------------------------------
    # 4. ENDPOINTS API REST (DRF)
    # --------------------------------------------------------------------------
    def test_api_public_request_and_consume_flow(self):
        """Flujo completo vía API REST: request-access y consume con OTP."""
        # 1. Solicitar OTP
        api_req_url = reverse("freedec:api-public-request-access")
        resp1 = self.client.post(
            api_req_url,
            {"file_hash": self.document.file_hash, "email": self.allowed_email},
            content_type="application/json",
        )
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp1.json()["status"], "processed")

        # 2. Obtener OTP
        token = AccessVerificationToken.objects.get(document=self.document, email=self.allowed_email)

        # 3. Consumir vía API
        api_consume_url = reverse("freedec:api-public-consume")
        resp2 = self.client.post(
            api_consume_url,
            {
                "file_hash": self.document.file_hash,
                "email": self.allowed_email,
                "otp_code": token.otp_code,
            },
            content_type="application/json",
        )
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.content, self.test_content)

    def test_admin_check_file_hash_view(self):
        """El endpoint AJAX de verificación previa de hash retorna metadatos y destinatarios pendientes."""
        self.client.force_login(self.superuser)
        url = reverse("admin:freedec_encrypteddocument_check_hash") + f"?hash={self.document.file_hash}"
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["exists"])
        self.assertFalse(data["is_consumed"])
        self.assertIn(self.allowed_email, data["pending_recipients"])

    def test_admin_delete_encrypted_document_cascade_and_shred(self):
        """
        La eliminación desde el panel de administración debe permitirse sin bloqueos de permisos
        en cascada, borrando tokens y registros asociados, y triturando el archivo físico en disco.
        """
        self.client.force_login(self.superuser)
        # Crear token y log asociados
        request_document_access(self.document.file_hash, self.allowed_email)
        physical_path = self.document.encrypted_file.path
        self.assertTrue(os.path.exists(physical_path))

        delete_url = reverse("admin:freedec_encrypteddocument_delete", args=[self.document.pk])
        # Confirmar borrado
        resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(resp.status_code, 302)

        # Verificar que el documento y sus relaciones ya no existen
        self.assertFalse(EncryptedDocument.objects.filter(pk=self.document.pk).exists())
        self.assertEqual(AccessVerificationToken.objects.filter(document_id=self.document.pk).count(), 0)
        self.assertEqual(DocumentAccessLog.objects.filter(document_id=self.document.pk).count(), 0)

        # Verificar trituración física en disco
        self.assertFalse(os.path.exists(physical_path))

    def test_admin_changelist_view_renders_correctly(self):
        """
        La vista de listado de EncryptedDocument en el Admin debe renderizar correctamente
        sin errores de formato (IndexError) para todas las políticas y estados (FIRST_ACCESS, ALL_RECIPIENTS y consumido).
        """
        self.client.force_login(self.superuser)

        # Crear un segundo documento con ALL_RECIPIENTS y consumo parcial
        second_file = SimpleUploadedFile("segundo_doc.pdf", b"%PDF-1.4\nsecond test content\n%%EOF\n")
        doc_all = upload_and_encrypt_document(
            second_file,
            allowed_emails=["u1@test.com", "u2@test.com"],
            burn_policy=EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
        )
        doc_all.consumed_recipients = ["u1@test.com"]
        doc_all.save()

        # Crear un tercer documento consumido para verificar badges y botones de documentos retirados
        third_file = SimpleUploadedFile("tercer_doc.pdf", b"%PDF-1.4\nthird test content\n%%EOF\n")
        doc_consumed = upload_and_encrypt_document(
            third_file,
            allowed_emails=["u3@test.com"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        )
        doc_consumed.is_consumed = True
        doc_consumed.consumed_by = "u3@test.com"
        doc_consumed.save()

        changelist_url = reverse("admin:freedec_encrypteddocument_changelist")
        resp = self.client.get(changelist_url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Descargado por 1/2 destinatarios")
        self.assertContains(resp, "1/2 descargados")
        self.assertContains(resp, "Plantilla")
        self.assertContains(resp, "Retirado")

        # Verificar también que el panel de auditoría en la vista de detalle de un documento consumido renderiza sin error
        change_consumed_url = reverse("admin:freedec_encrypteddocument_change", args=[doc_consumed.pk])
        resp_change = self.client.get(change_consumed_url)
        self.assertEqual(resp_change.status_code, 200)
        self.assertContains(resp_change, "Documento ya entregado")

    def test_admin_change_form_renders_corporate_email_template_and_allows_editing_description(self):
        """
        En el formulario de edición de EncryptedDocument en el Admin:
        - Se renderiza el panel de plantilla con textarea y botón de copiado.
        - Se permite modificar el campo de descripción y éste persiste al guardar.
        """
        self.client.force_login(self.superuser)
        change_url = reverse("admin:freedec_encrypteddocument_change", args=[self.document.pk])
        resp = self.client.get(change_url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Plantilla de Notificación por Correo Electrónico")
        self.assertContains(resp, "Copiar texto")
        self.assertContains(resp, self.document.file_hash)
        self.assertContains(resp, self.document.original_filename)

        # Modificar la descripción a través del POST
        log_count = self.document.access_logs.count()
        post_data = {
            "description": "Nueva descripción editada por el administrador",
            "allowed_emails": self.document.allowed_emails,
            "burn_policy": self.document.burn_policy,
            "access_logs-TOTAL_FORMS": str(log_count),
            "access_logs-INITIAL_FORMS": str(log_count),
            "access_logs-MIN_NUM_FORMS": "0",
            "access_logs-MAX_NUM_FORMS": "1000",
            "_save": "Guardar",
        }
        post_resp = self.client.post(change_url, post_data)
        self.assertEqual(post_resp.status_code, 302)

        self.document.refresh_from_db()
        self.assertEqual(self.document.description, "Nueva descripción editada por el administrador")

    def test_audit_log_view_only_user_cannot_delete(self):
        """Un usuario staff con permiso exclusivo de 'view' sobre registros de auditoría no puede eliminarlos."""
        view_only_user = User.objects.create_user(
            username="view_only_auditor",
            email="auditor_view@freedec.local",
            password="ViewPassword#2026",
            is_staff=True,
        )
        perm = Permission.objects.get(codename="view_documentaccesslog")
        view_only_user.user_permissions.add(perm)

        # Crear un registro de auditoría
        request_document_access(self.document.file_hash, self.allowed_email)
        log = DocumentAccessLog.objects.first()
        self.assertIsNotNone(log)

        self.client.force_login(view_only_user)
        # 1. Changelist de logs debe cargar pero sin la acción de eliminación
        resp = self.client.get(reverse("admin:freedec_documentaccesslog_changelist"))
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "delete_selected")

        # 2. Intento de eliminación directa debe responder 403 Forbidden
        delete_url = reverse("admin:freedec_documentaccesslog_delete", args=[log.pk])
        del_resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(del_resp.status_code, 403)
        self.assertTrue(DocumentAccessLog.objects.filter(pk=log.pk).exists())

    def test_encrypted_document_view_only_user_does_not_see_delete_button_and_cannot_delete(self):
        """Un usuario con permiso exclusivo de lectura sobre EncryptedDocument no ve el botón de eliminar y recibe 403 si intenta borrar."""
        doc_viewer = User.objects.create_user(
            username="doc_viewer_user",
            email="doc_viewer@freedec.local",
            password="DocViewerPassword#2026",
            is_staff=True,
        )
        perm = Permission.objects.get(codename="view_encrypteddocument")
        doc_viewer.user_permissions.add(perm)

        self.client.force_login(doc_viewer)
        # 1. En el changelist no debe mostrarse el botón de papelera
        resp = self.client.get(reverse("admin:freedec_encrypteddocument_changelist"))
        self.assertEqual(resp.status_code, 200)
        delete_url = reverse("admin:freedec_encrypteddocument_delete", args=[self.document.pk])
        self.assertNotContains(resp, f'href="{delete_url}"')

        # 2. Intento de borrado directo responde 403 Forbidden
        del_resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(del_resp.status_code, 403)
        self.assertTrue(EncryptedDocument.objects.filter(pk=self.document.pk).exists())

    def test_encrypted_document_delete_blocked_if_user_lacks_permission_on_related_logs(self):
        """Si el usuario tiene permiso para borrar documentos pero no para sus registros relacionados, Django bloquea el borrado."""
        partial_deleter = User.objects.create_user(
            username="partial_deleter_user",
            email="partial@freedec.local",
            password="PartialPassword#2026",
            is_staff=True,
        )
        perm_delete_doc = Permission.objects.get(codename="delete_encrypteddocument")
        perm_view_doc = Permission.objects.get(codename="view_encrypteddocument")
        partial_deleter.user_permissions.add(perm_delete_doc, perm_view_doc)

        # Crear log asociado
        request_document_access(self.document.file_hash, self.allowed_email)
        self.assertTrue(DocumentAccessLog.objects.filter(document_id=self.document.pk).exists())

        self.client.force_login(partial_deleter)
        delete_url = reverse("admin:freedec_encrypteddocument_delete", args=[self.document.pk])
        # Django debe bloquear la eliminación con 403 porque no tiene delete_documentaccesslog ni delete_accessverificationtoken
        resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(resp.status_code, 403)
        self.assertTrue(EncryptedDocument.objects.filter(pk=self.document.pk).exists())

    def test_encrypted_document_cascade_delete_allowed_for_document_deleter(self):
        """Un usuario con todos los permisos requeridos sobre los modelos en Django puede borrar el documento y sus dependencias."""
        doc_deleter = User.objects.create_user(
            username="doc_deleter_user",
            email="doc_deleter@freedec.local",
            password="DocDeleterPassword#2026",
            is_staff=True,
        )
        perm_delete_doc = Permission.objects.get(codename="delete_encrypteddocument")
        perm_view_doc = Permission.objects.get(codename="view_encrypteddocument")
        perm_delete_log = Permission.objects.get(codename="delete_documentaccesslog")
        perm_delete_tok = Permission.objects.get(codename="delete_accessverificationtoken")
        doc_deleter.user_permissions.add(perm_delete_doc, perm_view_doc, perm_delete_log, perm_delete_tok)

        request_document_access(self.document.file_hash, self.allowed_email)
        self.assertTrue(DocumentAccessLog.objects.filter(document_id=self.document.pk).exists())

        self.client.force_login(doc_deleter)
        delete_url = reverse("admin:freedec_encrypteddocument_delete", args=[self.document.pk])
        resp = self.client.post(delete_url, {"post": "yes"})
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(EncryptedDocument.objects.filter(pk=self.document.pk).exists())
        self.assertEqual(DocumentAccessLog.objects.filter(document_id=self.document.pk).count(), 0)



