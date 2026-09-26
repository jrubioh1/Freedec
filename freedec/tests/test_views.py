import hashlib
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

    def setUp(self):
        self.admin_user = User.objects.create_user(
            username="admin_sec",
            email="admin@freedec.local",
            password="StrongAdminPassword#2026",
        )
        self.upload_url = reverse("freedec:admin-upload")
        self.public_request_url = reverse("freedec:public-request-password")
        self.gui_public_url = reverse("freedec:gui-public-request")
        self.gui_admin_url = reverse("freedec:gui-admin-upload")
        self.sample_bytes = MINIMAL_VALID_PDF
        self.expected_hash = hashlib.sha256(self.sample_bytes).hexdigest()

    # --------------------------------------------------------------------------
    # PRUEBAS DE LA API REST (DRF)
    # --------------------------------------------------------------------------
    def test_admin_upload_unauthenticated_fails(self):
        """Un usuario anónimo debe ser rechazado en la API REST de subida."""
        file_data = SimpleUploadedFile("report.pdf", self.sample_bytes)
        response = self.client.post(
            self.upload_url,
            {
                "original_file": file_data,
                "plain_password": "PlainSecretPassword123!",
                "allowed_emails": "audit@corp.com",
            },
            format="multipart",
        )
        self.assertIn(
            response.status_code,
            [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN],
        )

    def test_admin_upload_rejects_unauthorized_format(self):
        """Un formato no autorizado (ej. .txt o .exe) debe ser rechazado con 400 Bad Request."""
        self.client.force_authenticate(user=self.admin_user)
        file_data = SimpleUploadedFile("script.sh", b"#!/bin/bash\necho hello")
        response = self.client.post(
            self.upload_url,
            {
                "original_file": file_data,
                "plain_password": "StrongSecretPassword#888",
                "allowed_emails": ["auditor@corp.com"],
            },
            format="multipart",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("original_file", response.json())

    def test_admin_upload_authenticated_success(self):
        """Un administrador autenticado sube el documento PDF, recibe hash y access_code."""
        self.client.force_authenticate(user=self.admin_user)
        file_data = SimpleUploadedFile("report.pdf", self.sample_bytes)
        response = self.client.post(
            self.upload_url,
            {
                "original_file": file_data,
                "plain_password": "StrongSecretPassword#888",
                "allowed_emails": ["auditor1@corp.com", "director@corp.com"],
            },
            format="multipart",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        data = response.json()
        self.assertEqual(data["file_hash"], self.expected_hash)
        self.assertIn("access_code", data)
        self.assertTrue(len(data["access_code"]) > 20)
        self.assertIn("encrypted_file_url", data)
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
        self.assertContains(response, "Recuperación Segura de Contraseña")

    def test_gui_admin_upload_unauthenticated_redirects(self):
        """El portal de subida web exige autenticación y redirige a login si no está autenticado."""
        response = self.client.get(self.gui_admin_url)
        self.assertEqual(response.status_code, 302)  # Redirección a login

    def test_gui_admin_upload_authenticated_post(self):
        """Un admin autenticado puede subir y cifrar archivos a través del formulario web."""
        self.client.force_login(self.admin_user)
        file_data = SimpleUploadedFile("gui_report.pdf", self.sample_bytes)
        response = self.client.post(
            self.gui_admin_url,
            {
                "original_file": file_data,
                "plain_password": "WebGuiPassword#2026",
                "allowed_emails": "webuser@corp.com, admin@corp.com",
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertContains(response, "Documento cifrado y registrado exitosamente", status_code=201)
        self.assertContains(response, self.expected_hash, status_code=201)

    def test_gui_admin_upload_multiple_email_fields(self):
        """El formulario web procesa múltiples inputs dinámicos con name='allowed_emails'."""
        self.client.force_login(self.admin_user)
        file_data = SimpleUploadedFile("multi_email_report.pdf", self.sample_bytes)
        # Simula el envío de múltiples campos input name="allowed_emails"
        from django.http import QueryDict
        qd = QueryDict(mutable=True)
        qd.setlist("allowed_emails", ["auditor_a@corp.com", "auditor_b@corp.com"])
        qd["plain_password"] = "SecretMultiPass#2026"
        
        post_data = qd.dict()
        post_data["allowed_emails"] = qd.getlist("allowed_emails")
        post_data["original_file"] = file_data

        response = self.client.post(
            self.gui_admin_url,
            post_data,
        )
        self.assertEqual(response.status_code, 201)
        self.assertContains(response, "auditor_a@corp.com", status_code=201)
        self.assertContains(response, "auditor_b@corp.com", status_code=201)
