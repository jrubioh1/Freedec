import hashlib
import io
import zipfile
from cryptography.fernet import Fernet
from django.core import mail
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from freedec.models import EncryptedDocument
from freedec.services import (
    DocumentManagementService,
    FernetCryptoService,
    calculate_file_sha256,
)
from freedec.validators import validate_document_file, validate_safe_email

TEST_FERNET_KEY = Fernet.generate_key().decode()

MINIMAL_TEST_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


def create_minimal_odt_bytes() -> bytes:
    """Crea en memoria una estructura binaria válida de LibreOffice Writer (.odt)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        zf.writestr("content.xml", "<document-content></document-content>")
    return buf.getvalue()


def create_minimal_docx_bytes() -> bytes:
    """Crea en memoria una estructura binaria válida de Microsoft Word (.docx)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/document.xml", "<document></document>")
    return buf.getvalue()


@override_settings(FREEDEC_FERNET_KEY=TEST_FERNET_KEY, TESTING=True)
class FreedecServicesSecurityTestCase(TestCase):
    """Pruebas unitarias de ciberseguridad, formatos y servicios de Freedec."""

    def setUp(self):
        self.crypto_service = FernetCryptoService(key=TEST_FERNET_KEY)
        self.doc_service = DocumentManagementService(crypto_service=self.crypto_service)
        self.test_content = MINIMAL_TEST_PDF
        self.expected_sha256 = hashlib.sha256(self.test_content).hexdigest()

    def test_format_validation_pdf(self):
        """Un archivo PDF legítimo debe ser aceptado."""
        pdf_file = SimpleUploadedFile("document.pdf", self.test_content)
        validated = validate_document_file(pdf_file)
        self.assertIsNotNone(validated)

    def test_format_validation_libreoffice_odt(self):
        """Un archivo LibreOffice .odt válido con estructura ODF debe ser aceptado."""
        odt_bytes = create_minimal_odt_bytes()
        odt_file = SimpleUploadedFile("informe.odt", odt_bytes)
        validated = validate_document_file(odt_file)
        self.assertIsNotNone(validated)

    def test_format_validation_msoffice_docx(self):
        """Un archivo Microsoft Office .docx válido con OpenXML debe ser aceptado."""
        docx_bytes = create_minimal_docx_bytes()
        docx_file = SimpleUploadedFile("contrato.docx", docx_bytes)
        validated = validate_document_file(docx_file)
        self.assertIsNotNone(validated)

    def test_format_validation_reject_unauthorized_extensions(self):
        """Formatos no autorizados (.exe, .txt, .sh) deben ser rechazados inmediatamente."""
        exe_file = SimpleUploadedFile("malware.exe", b"MZ\x90\x00BinaryData")
        with self.assertRaises(ValidationError):
            validate_document_file(exe_file)

        txt_file = SimpleUploadedFile("documento.txt", b"Texto plano no permitido")
        with self.assertRaises(ValidationError):
            validate_document_file(txt_file)

    def test_format_validation_reject_spoofed_magic_bytes(self):
        """Un archivo renombrado a .pdf pero con contenido no-PDF debe ser detectado y rechazado."""
        spoofed_file = SimpleUploadedFile("falso.pdf", b"Contenido corrupto o malicioso sin cabecera PDF")
        with self.assertRaises(ValidationError):
            validate_document_file(spoofed_file)

    def test_email_validation_anti_crlf_injection(self):
        """Intento de inyección de cabeceras CRLF en correo debe ser bloqueado."""
        valid_email = "usuario@empresa.com"
        self.assertEqual(validate_safe_email(valid_email), "usuario@empresa.com")

        malicious_email = "victima@empresa.com\r\nBcc: atacante@evil.com"
        with self.assertRaises(ValidationError):
            validate_safe_email(malicious_email)

    def test_calculate_file_sha256_streaming(self):
        """Verifica que el cálculo SHA-256 sea exacto y preserve el puntero del stream."""
        file_obj = io.BytesIO(self.test_content)
        calculated = calculate_file_sha256(file_obj)
        self.assertEqual(calculated, self.expected_sha256)
        self.assertEqual(file_obj.read(), self.test_content)

    def test_fernet_crypto_bytes_and_string(self):
        """Verifica el cifrado simétrico y descifrado de bytes y strings."""
        encrypted_bytes = self.crypto_service.encrypt_bytes(self.test_content)
        self.assertNotEqual(encrypted_bytes, self.test_content)
        decrypted_bytes = self.crypto_service.decrypt_bytes(encrypted_bytes)
        self.assertEqual(decrypted_bytes, self.test_content)

        secret_text = "MasterPassword#2026_Secure!"
        encrypted_str = self.crypto_service.encrypt_string(secret_text)
        decrypted_str = self.crypto_service.decrypt_string(encrypted_str)
        self.assertEqual(decrypted_str, secret_text)

    def test_fernet_tamper_resistance(self):
        """Verifica que modificar un solo bit del contenido cifrado sea detectado como alteración."""
        encrypted_bytes = bytearray(self.crypto_service.encrypt_bytes(self.test_content))
        encrypted_bytes[20] ^= 0xFF
        with self.assertRaises(ValueError):
            self.crypto_service.decrypt_bytes(bytes(encrypted_bytes))

    def test_admin_upload_and_zero_knowledge_storage(self):
        """Verifica que el archivo y contraseña se cifren y el código se almacene hasheado (Zero-Knowledge)."""
        uploaded = SimpleUploadedFile("secret.pdf", self.test_content)
        plain_password = "MySuperSecretPassword123!"
        emails = ["Alice@Example.COM", "  bob@domain.org "]

        doc, raw_access_code = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password=plain_password,
            allowed_emails=emails,
        )

        self.assertEqual(doc.file_hash, self.expected_sha256)
        self.assertNotEqual(doc.access_code, raw_access_code)
        self.assertTrue(doc.access_code.startswith("pbkdf2_sha256$"))
        self.assertTrue(doc.verify_access_code(raw_access_code))
        self.assertNotEqual(doc.encrypted_password, plain_password)
        self.assertEqual(
            self.crypto_service.decrypt_string(doc.encrypted_password),
            plain_password,
        )
        self.assertIn("alice@example.com", doc.allowed_emails)
        self.assertIn("bob@domain.org", doc.allowed_emails)

    def test_public_verify_and_dispatch_success(self):
        """Verifica que un usuario con el archivo original, código y correo reciba la clave por email."""
        uploaded = SimpleUploadedFile("secret.pdf", self.test_content)
        plain_password = "UnlockSecretKey!777"
        emails = ["victim-target@security.org"]

        doc, raw_access_code = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password=plain_password,
            allowed_emails=emails,
        )

        user_uploaded = SimpleUploadedFile("local_copy.pdf", self.test_content)
        success, message = self.doc_service.verify_and_dispatch_password(
            uploaded_file=user_uploaded,
            access_code=raw_access_code,
            recipient_email="Victim-Target@Security.ORG",
        )

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        self.assertIn("victim-target@security.org", sent_email.to)
        self.assertIn(plain_password, sent_email.body)
        self.assertIn(self.expected_sha256[:12], sent_email.subject)

    def test_public_verify_invalid_file_hash(self):
        """Verifica que un archivo con contenido diferente no active el envío de contraseña."""
        other_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj<</Different content>>endobj\n"
            b"xref\n0 2\n0000000000 65535 f \n0000000010 00000 n \n"
            b"trailer<</Size 2/Root 1 0 R>>\nstartxref\n50\n%%EOF\n"
        )
        wrong_file = SimpleUploadedFile("fake.pdf", other_pdf)
        success, message = self.doc_service.verify_and_dispatch_password(
            uploaded_file=wrong_file,
            access_code="any-code",
            recipient_email="someone@example.com",
        )

        self.assertTrue(success)  # Respuesta neutra anti-enumeración
        self.assertEqual(len(mail.outbox), 0)
