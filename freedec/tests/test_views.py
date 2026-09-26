import hashlib
import shutil
import tempfile
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from freedec.models import DocumentAccessLog, EncryptedDocument
from freedec.services import DocumentManagementService

User = get_user_model()
TEST_FERNET_KEY = Fernet.generate_key().decode()

MINIMAL_VALID_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


@override_settings(FREEDEC_FERNET_KEY=TEST_FERNET_KEY, TESTING=True)
class FreedecViewsAPITestCase(APITestCase):
    """Pruebas de integración para API REST, Panel de Administración Django e Interfaz Gráfica Web (GUI)."""

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
        self.admin_user = User.objects.create_superuser(
            username="admin_sec",
            email="admin@freedec.local",
            password="StrongAdminPassword#2026",
        )
        self.django_admin_add_url = reverse("admin:freedec_encrypteddocument_add")
        self.public_request_url = reverse("freedec:public-request-access")
        self.public_consume_url = reverse("freedec:api-public-consume")
        self.gui_public_url = reverse("freedec:gui-public-request")
        self.gui_consume_url = reverse("freedec:gui-consume")
        self.sample_bytes = MINIMAL_VALID_PDF
        self.expected_hash = hashlib.sha256(self.sample_bytes).hexdigest()
        self.service = DocumentManagementService()

    # --------------------------------------------------------------------------
    # PRUEBAS DEL PANEL DE ADMINISTRACIÓN DE DJANGO (ADMIN)
    # --------------------------------------------------------------------------
    def test_admin_upload_unauthenticated_redirects(self):
        """Un usuario anónimo debe ser redirigido al login al intentar acceder al admin."""
        response = self.client.get(self.django_admin_add_url)
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertIn("/admin/login/", response.url)

    def test_admin_upload_authenticated_success(self):
        """Un administrador autenticado sube el documento PDF vía Django Admin y se cifra con DEK."""
        self.client.force_login(self.admin_user)
        file_data = SimpleUploadedFile("report.pdf", self.sample_bytes)
        response = self.client.post(
            self.django_admin_add_url,
            {
                "original_file": file_data,
                "allowed_emails": ["auditor1@corp.com", "director@corp.com"],
            },
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        doc = EncryptedDocument.objects.filter(file_hash=self.expected_hash).first()
        self.assertIsNotNone(doc)
        self.assertIn("auditor1@corp.com", doc.allowed_emails)
        self.assertIn("director@corp.com", doc.allowed_emails)
        self.assertIn("auditor1@corp.com", doc.user_envelopes)
        self.assertFalse(doc.is_consumed)

    def test_admin_download_authenticated_preserves_file(self):
        """Un administrador descarga el archivo descifrado desde el panel sin destruirlo (Audit Bypass)."""
        uploaded = SimpleUploadedFile("confidential_admin.pdf", self.sample_bytes)
        doc, _ = self.service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["client@domain.com"],
        )
        storage = doc.encrypted_file.storage
        file_path = doc.encrypted_file.name

        self.client.force_login(self.admin_user)
        download_url = reverse("admin:freedec_encrypteddocument_admin_download", args=[doc.pk])
        response = self.client.get(download_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, self.sample_bytes)
        self.assertIn("attachment; filename=", response.headers.get("Content-Disposition", ""))

        # Verificar que el archivo NO se destruyó y NO está marcado como consumido
        self.assertTrue(storage.exists(file_path))
        doc.refresh_from_db()
        self.assertFalse(doc.is_consumed)

        # Verificar auditoría administrativa
        log = DocumentAccessLog.objects.filter(document=doc, action="admin_inspeccion_preservada").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.email, self.admin_user.email)

    def test_admin_download_unauthenticated_redirects(self):
        """La descarga administrativa no es accesible de forma anónima."""
        uploaded = SimpleUploadedFile("secret_anon.pdf", self.sample_bytes)
        doc, _ = self.service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["target@corp.com"],
        )
        download_url = reverse("admin:freedec_encrypteddocument_admin_download", args=[doc.pk])
        response = self.client.get(download_url)
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)

    # --------------------------------------------------------------------------
    # PRUEBAS DE LA API REST (DRF)
    # --------------------------------------------------------------------------
    def test_api_public_request_access_success(self):
        """El endpoint público procesa la subida y envía Magic Link + OTP por email."""
        uploaded = SimpleUploadedFile("audit.pdf", self.sample_bytes)
        doc, _ = self.service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["client@domain.com"],
        )

        public_file = SimpleUploadedFile("audit.pdf", self.sample_bytes)
        response = self.client.post(
            self.public_request_url,
            {
                "file": public_file,
                "email": "client@domain.com",
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["status"], "processed")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("/freedec/consumir/?t=", mail.outbox[0].body)
        self.assertIn("CÓDIGO OTP:", mail.outbox[0].body)

    def test_api_public_consume_with_token_burns_file(self):
        """El endpoint API de consumo descifra con token y destruye físicamente el binario (Burn-After-Read)."""
        uploaded = SimpleUploadedFile("api_burn.pdf", self.sample_bytes)
        doc, _ = self.service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["api_user@test.org"],
        )
        storage = doc.encrypted_file.storage
        file_path = doc.encrypted_file.name

        doc.encrypted_file.seek(0)
        enc_copy = SimpleUploadedFile("api_burn.enc", doc.encrypted_file.read())
        self.service.request_document_access(
            uploaded_file=enc_copy,
            recipient_email="api_user@test.org",
        )
        token_str = mail.outbox[-1].body.split("?t=")[1].split()[0]

        # Consumo mediante API GET ?t=...
        response = self.client.get(f"{self.public_consume_url}?t={token_str}")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, self.sample_bytes)

        # Verificar destrucción física en disco
        self.assertFalse(storage.exists(file_path))
        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)
        self.assertEqual(doc.consumed_by, "api_user@test.org")

    def test_api_public_consume_with_otp_burns_file(self):
        """El endpoint API de consumo admite POST con código OTP de 6 dígitos y email."""
        uploaded = SimpleUploadedFile("api_otp_burn.pdf", self.sample_bytes)
        doc, _ = self.service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["otp_api@test.org"],
        )
        storage = doc.encrypted_file.storage
        file_path = doc.encrypted_file.name

        doc.encrypted_file.seek(0)
        enc_copy = SimpleUploadedFile("api_otp_burn.enc", doc.encrypted_file.read())
        self.service.request_document_access(
            uploaded_file=enc_copy,
            recipient_email="otp_api@test.org",
        )

        token_obj = doc.tokens.first()
        otp = token_obj.otp_code

        response = self.client.post(
            self.public_consume_url,
            {
                "otp_code": otp,
                "email": "otp_api@test.org",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, self.sample_bytes)

        self.assertFalse(storage.exists(file_path))
        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)

    def test_api_public_consume_invalid_token_returns_400(self):
        """Un token inexistente devuelve error 400."""
        response = self.client.get(f"{self.public_consume_url}?t=nonexistent_token_123")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # --------------------------------------------------------------------------
    # PRUEBAS DE LA INTERFAZ GRÁFICA WEB (GUI)
    # --------------------------------------------------------------------------
    def test_gui_public_request_get(self):
        """El portal web público carga correctamente con código 200."""
        response = self.client.get(self.gui_public_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Solicitar Acceso al Documento")

    def test_gui_public_request_post_success(self):
        """El portal web público procesa la subida de .enc y envía las credenciales."""
        uploaded = SimpleUploadedFile("gui_test.pdf", self.sample_bytes)
        doc, _ = self.service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["gui_user@domain.com"],
        )
        doc.encrypted_file.seek(0)
        enc_file_data = SimpleUploadedFile("gui_test.enc", doc.encrypted_file.read())

        response = self.client.post(
            self.gui_public_url,
            {
                "file": enc_file_data,
                "email": "gui_user@domain.com",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("gui_user@domain.com", mail.outbox[0].to)

    def test_gui_public_consume_get(self):
        """La vista web para consumir carga correctamente con código 200 y formulario OTP."""
        response = self.client.get(self.gui_consume_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Consumo y Descarga Segura (Burn-After-Read)")
        self.assertContains(response, "Código OTP")

    def test_gui_public_consume_magic_link_burns_file(self):
        """Acceder mediante Magic Link (?t=...) entrega el binario original y quema el archivo."""
        uploaded = SimpleUploadedFile("magic_gui.pdf", self.sample_bytes)
        doc, _ = self.service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["magic@user.com"],
        )
        storage = doc.encrypted_file.storage
        file_path = doc.encrypted_file.name

        doc.encrypted_file.seek(0)
        enc_file = SimpleUploadedFile("magic_gui.enc", doc.encrypted_file.read())
        self.service.request_document_access(
            uploaded_file=enc_file,
            recipient_email="magic@user.com",
        )
        token_str = mail.outbox[-1].body.split("?t=")[1].split()[0]

        response = self.client.get(f"{self.gui_consume_url}?t={token_str}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.sample_bytes)
        self.assertIn("attachment; filename=", response.headers.get("Content-Disposition", ""))

        self.assertFalse(storage.exists(file_path))
        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)

    def test_gui_public_consume_otp_post_burns_file(self):
        """Enviar formulario con código OTP y email descarga el binario original y quema el archivo."""
        uploaded = SimpleUploadedFile("otp_gui.pdf", self.sample_bytes)
        doc, _ = self.service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["otp_gui@user.com"],
        )
        storage = doc.encrypted_file.storage
        file_path = doc.encrypted_file.name

        doc.encrypted_file.seek(0)
        enc_file = SimpleUploadedFile("otp_gui.enc", doc.encrypted_file.read())
        self.service.request_document_access(
            uploaded_file=enc_file,
            recipient_email="otp_gui@user.com",
        )

        otp = doc.tokens.first().otp_code

        response = self.client.post(
            self.gui_consume_url,
            {
                "otp_code": otp,
                "email": "otp_gui@user.com",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.sample_bytes)

        self.assertFalse(storage.exists(file_path))
        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)

    def test_gui_public_consume_post_invalid_otp(self):
        """Descifrar con OTP incorrecto devuelve error 400 y mensaje en pantalla."""
        response = self.client.post(
            self.gui_consume_url,
            {
                "otp_code": "000000",
                "email": "user@example.com",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "El enlace de acceso o código OTP es inválido", status_code=400)

    def test_gui_public_consume_already_consumed_document(self):
        """Intentar consumir un documento ya retirado muestra aviso informando del consumo previo."""
        uploaded = SimpleUploadedFile("already_burned.pdf", self.sample_bytes)
        doc, _ = self.service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["user1@example.com", "user2@example.com"],
        )
        doc.encrypted_file.seek(0)
        enc_file = SimpleUploadedFile("already_burned.enc", doc.encrypted_file.read())
        
        # User 1 requests access
        self.service.request_document_access(uploaded_file=enc_file, recipient_email="user1@example.com")
        token_str1 = mail.outbox[-1].body.split("?t=")[1].split()[0]
        
        # User 2 requests access
        enc_file.seek(0)
        self.service.request_document_access(uploaded_file=enc_file, recipient_email="user2@example.com")
        token_str2 = mail.outbox[-1].body.split("?t=")[1].split()[0]

        # User 1 consumes and burns it
        self.client.get(f"{self.gui_consume_url}?t={token_str1}")
        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)

        # User 2 tries to consume using their token
        response = self.client.get(f"{self.gui_consume_url}?t={token_str2}")
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "El documento ya fue retirado por user1@example.com", status_code=400)
