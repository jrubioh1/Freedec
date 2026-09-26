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

from freedec.models import EncryptedDocument
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
    """Pruebas de integración para API REST e Interfaz Gráfica Web (GUI)."""

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
        self.public_request_url = reverse("freedec:public-request-password")
        self.gui_public_url = reverse("freedec:gui-public-request")
        self.gui_decrypt_url = reverse("freedec:gui-public-decrypt")
        self.sample_bytes = MINIMAL_VALID_PDF
        self.expected_hash = hashlib.sha256(self.sample_bytes).hexdigest()

    # --------------------------------------------------------------------------
    # PRUEBAS DEL PANEL DE ADMINISTRACIÓN DE DJANGO (ADMIN)
    # --------------------------------------------------------------------------
    def test_admin_upload_unauthenticated_redirects(self):
        """Un usuario anónimo debe ser redirigido al login al intentar acceder al admin."""
        response = self.client.get(self.django_admin_add_url)
        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertIn("/admin/login/", response.url)

    def test_admin_upload_authenticated_success(self):
        """Un administrador autenticado sube el documento PDF vía Django Admin y se cifra."""
        self.client.force_login(self.admin_user)
        file_data = SimpleUploadedFile("report.pdf", self.sample_bytes)
        response = self.client.post(
            self.django_admin_add_url,
            {
                "original_file": file_data,
                "plain_password": "StrongSecretPassword#888",
                "allowed_emails": ["auditor1@corp.com", "director@corp.com"],
            },
            follow=True,
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(EncryptedDocument.objects.filter(file_hash=self.expected_hash).exists())

    def test_public_request_password_endpoint(self):
        """El endpoint público procesa la subida sin requerir token JWT/sesión."""
        service = DocumentManagementService()
        uploaded = SimpleUploadedFile("audit.pdf", self.sample_bytes)
        doc, raw_access_code = service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password="FinalPassword999!",
            allowed_emails=["client@domain.com"],
        )

        public_file = SimpleUploadedFile("audit.pdf", self.sample_bytes)
        response = self.client.post(
            self.public_request_url,
            {
                "file": public_file,
                "access_code": raw_access_code,
                "email": "client@domain.com",
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["status"], "processed")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("FinalPassword999!", mail.outbox[0].body)

    # --------------------------------------------------------------------------
    # PRUEBAS DE LA INTERFAZ GRÁFICA WEB (GUI)
    # --------------------------------------------------------------------------
    def test_gui_public_request_get(self):
        """El portal web público carga correctamente con código 200."""
        response = self.client.get(self.gui_public_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Entrega Segura de Contraseña")

    def test_gui_public_decrypt_get(self):
        """La vista web para descifrar carga correctamente con código 200."""
        response = self.client.get(self.gui_decrypt_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Descifrar Archivo Cifrado")

    def test_gui_public_decrypt_post_success(self):
        """Descifrar un archivo .enc con la contraseña correcta devuelve el archivo binario original."""
        from freedec.services import DocumentManagementService
        service = DocumentManagementService()
        uploaded = SimpleUploadedFile("contract.pdf", self.sample_bytes)
        doc, _ = service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password="SecretDecrypt123!",
            allowed_emails=["user@example.com"],
        )
        doc.encrypted_file.seek(0)
        enc_file_data = SimpleUploadedFile("doc.enc", doc.encrypted_file.read())

        response = self.client.post(
            self.gui_decrypt_url,
            {
                "file": enc_file_data,
                "password": "SecretDecrypt123!",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.sample_bytes)
        self.assertIn("attachment;", response.headers.get("Content-Disposition", ""))

    def test_gui_public_decrypt_post_wrong_password(self):
        """Descifrar con contraseña incorrecta devuelve error 400 y mensaje en pantalla."""
        from freedec.services import DocumentManagementService
        service = DocumentManagementService()
        uploaded = SimpleUploadedFile("secret.pdf", self.sample_bytes)
        doc, _ = service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password="CorrectPassword123!",
            allowed_emails=["user@example.com"],
        )
        doc.encrypted_file.seek(0)
        enc_file_data = SimpleUploadedFile("doc.enc", doc.encrypted_file.read())

        response = self.client.post(
            self.gui_decrypt_url,
            {
                "file": enc_file_data,
                "password": "IncorrectPassword999!",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "La contraseña introducida no coincide", status_code=400)
