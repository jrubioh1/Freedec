import hashlib
import io
import zipfile
import shutil
import tempfile
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
        self.assertIn("Clave de recuperación", sent_email.subject)

    def test_public_verify_with_enc_file(self):
        """Verifica que un usuario pueda subir el archivo .enc cifrado para solicitar la clave."""
        uploaded = SimpleUploadedFile("secret_for_enc.pdf", self.test_content)
        plain_password = "EncPassword#888"
        emails = ["enc-recipient@security.org"]

        doc, raw_access_code = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password=plain_password,
            allowed_emails=emails,
        )

        # Leer los bytes del archivo .enc cifrado
        doc.encrypted_file.seek(0)
        enc_bytes = doc.encrypted_file.read()
        uploaded_enc = SimpleUploadedFile("distributed_file.enc", enc_bytes)

        # El usuario sube el archivo .enc junto con el access_code y su email
        success, message = self.doc_service.verify_and_dispatch_password(
            uploaded_file=uploaded_enc,
            access_code=raw_access_code,
            recipient_email="enc-recipient@security.org",
        )

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[-1]
        self.assertIn("enc-recipient@security.org", sent_email.to)
        self.assertIn(plain_password, sent_email.body)

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

    def test_auto_generated_password(self):
        """Verifica que si no se proporciona contraseña, se genera automáticamente una de 24 caracteres."""
        uploaded = SimpleUploadedFile("auto_pwd.pdf", self.test_content)
        doc, raw_access_code = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password=None,
            allowed_emails=["auto@test.local"],
        )
        self.assertTrue(hasattr(doc, "generated_password"))
        self.assertEqual(len(doc.generated_password), 24)
        decrypted = self.crypto_service.decrypt_string(doc.encrypted_password)
        self.assertEqual(decrypted, doc.generated_password)

    def test_file_renaming_does_not_affect_hash(self):
        """Demuestra que renombrar el archivo no altera el hash SHA-256 ni la verificación."""
        file1 = SimpleUploadedFile("nombre_original_del_archivo.pdf", self.test_content)
        file2 = SimpleUploadedFile("nombre_completamente_cambiado_por_usuario.pdf", self.test_content)
        hash1 = calculate_file_sha256(file1)
        hash2 = calculate_file_sha256(file2)
        self.assertEqual(hash1, hash2)

    def test_physical_file_deleted_on_model_delete(self):
        """Verifica que al eliminar un modelo EncryptedDocument se borra el archivo físico de disco."""
        uploaded = SimpleUploadedFile("file_to_delete.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password="SecretToDelete123!",
            allowed_emails=["del@test.local"],
        )
        storage = doc.encrypted_file.storage
        file_name = doc.encrypted_file.name
        self.assertTrue(storage.exists(file_name))

        # Borrado individual
        doc.delete()
        self.assertFalse(storage.exists(file_name))

    def test_physical_file_deleted_on_queryset_delete(self):
        """Verifica que al eliminar mediante QuerySet.delete() se borra el archivo físico."""
        uploaded = SimpleUploadedFile("bulk_delete.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password="BulkSecret123!",
            allowed_emails=["bulk@test.local"],
        )
        storage = doc.encrypted_file.storage
        file_name = doc.encrypted_file.name
        self.assertTrue(storage.exists(file_name))

        # Borrado masivo (QuerySet)
        EncryptedDocument.objects.filter(id=doc.id).delete()
        self.assertFalse(storage.exists(file_name))

    def test_decrypt_document_with_password_success(self):
        """Verifica el descifrado exitoso del archivo .enc usando la contraseña correcta."""
        uploaded = SimpleUploadedFile("contract.pdf", self.test_content)
        password = "PasswordForDecryptTest#2026!"
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password=password,
            allowed_emails=["client@company.com"],
        )
        # Tomar el archivo cifrado generado
        doc.encrypted_file.seek(0)
        enc_file_obj = SimpleUploadedFile("doc.enc", doc.encrypted_file.read())

        success, decrypted_bytes, filename, mimetype, msg = (
            self.doc_service.decrypt_document_with_password(
                encrypted_file_obj=enc_file_obj,
                password=password,
            )
        )
        self.assertTrue(success)
        self.assertEqual(decrypted_bytes, self.test_content)
        self.assertTrue(filename.endswith(".pdf"))
        self.assertEqual(mimetype, "application/pdf")

    def test_decrypt_document_with_wrong_password(self):
        """Verifica que con contraseña incorrecta el descifrado falla y no devuelve contenido."""
        uploaded = SimpleUploadedFile("confidential.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password="CorrectPassword123!",
            allowed_emails=["client@company.com"],
        )
        doc.encrypted_file.seek(0)
        enc_file_obj = SimpleUploadedFile("doc.enc", doc.encrypted_file.read())

        success, decrypted_bytes, filename, mimetype, msg = (
            self.doc_service.decrypt_document_with_password(
                encrypted_file_obj=enc_file_obj,
                password="WrongPassword999!",
            )
        )
        self.assertFalse(success)
        self.assertIsNone(decrypted_bytes)

    def test_original_filename_and_enc_naming(self):
        """El registro guarda el nombre original y el archivo cifrado preserva el nombre con sufijo .enc."""
        uploaded = SimpleUploadedFile("balance_anual_2026.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password="Password123!",
            allowed_emails=["finance@test.local"],
        )
        self.assertEqual(doc.original_filename, "balance_anual_2026.pdf")
        self.assertIn("balance_anual_2026.pdf", doc.encrypted_file.name)
        self.assertTrue(doc.encrypted_file.name.endswith(".enc"))

    def test_access_tracking_and_audit_logging(self):
        """Verifica que al solicitar la contraseña se actualiza el contador, fecha de acceso y tabla de auditoría."""
        from freedec.models import DocumentAccessLog
        uploaded = SimpleUploadedFile("contrato_rrhh.pdf", self.test_content)
        doc, access_code = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password="SecretHR#2026!",
            allowed_emails=["empleado@empresa.com"],
        )
        self.assertEqual(doc.access_count, 0)
        self.assertIsNone(doc.last_accessed_at)

        # Simular petición de contraseña con IP
        uploaded.seek(0)
        success, _ = self.doc_service.verify_and_dispatch_password(
            uploaded_file=uploaded,
            access_code=access_code,
            recipient_email="empleado@empresa.com",
            client_ip="192.168.1.50",
        )
        self.assertTrue(success)

        doc.refresh_from_db()
        self.assertEqual(doc.access_count, 1)
        self.assertIsNotNone(doc.last_accessed_at)
        self.assertEqual(doc.last_accessed_by, "empleado@empresa.com")

        # Verificar registro en DocumentAccessLog
        logs = DocumentAccessLog.objects.filter(document=doc)
        self.assertEqual(logs.count(), 1)
        log = logs.first()
        self.assertEqual(log.email, "empleado@empresa.com")
        self.assertEqual(log.action, "solicitud_clave")
        self.assertEqual(log.ip_address, "192.168.1.50")

    def test_email_specifies_document_name(self):
        """El correo enviado al destinatario indica claramente el nombre del documento."""
        uploaded = SimpleUploadedFile("auditoria_seguridad.pdf", self.test_content)
        doc, access_code = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            plain_password="AuditPassword777!",
            allowed_emails=["auditor@ciberseguridad.local"],
        )
        uploaded.seek(0)
        self.doc_service.verify_and_dispatch_password(
            uploaded_file=uploaded,
            access_code=access_code,
            recipient_email="auditor@ciberseguridad.local",
        )
        self.assertEqual(len(mail.outbox), 1)
        sent = mail.outbox[0]
        self.assertIn("auditoria_seguridad.pdf", sent.subject)
        self.assertIn("auditoria_seguridad.pdf", sent.body)
