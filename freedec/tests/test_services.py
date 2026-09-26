import hashlib
import io
import os
import shutil
import tempfile
import zipfile
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone

from freedec.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from freedec.services import (
    DocumentManagementService,
    FernetCryptoService,
    calculate_file_sha256,
)
from freedec.validators import validate_document_file, validate_safe_email

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
    """Pruebas unitarias de ciberseguridad, criptografía DEK/KEK y servicios de Freedec."""

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
        self.admin_user = User.objects.create_superuser(
            username="admin_test",
            email="admin@freedec.local",
            password="StrongPassword#2026",
        )

    # --------------------------------------------------------------------------
    # VALIDACIONES DE FORMATO Y CONTENIDO (OWASP A03 / A08)
    # --------------------------------------------------------------------------
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

    # --------------------------------------------------------------------------
    # CRIPTOGRAFÍA SIMÉTRICA FERNET Y RESISTENCIA A MANIPULACIÓN
    # --------------------------------------------------------------------------
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

    # --------------------------------------------------------------------------
    # ARQUITECTURA CRIPTOGRÁFICA DEK + SOBRES DIGITALES (user_envelopes)
    # --------------------------------------------------------------------------
    def test_upload_and_encrypt_document_dek_architecture(self):
        """
        Verifica la arquitectura DEK multi-usuario:
        - Cifrado único con DEK.
        - Generación de sobres digitales por cada correo en allowed_emails.
        - Capacidad de descifrado administrativo con settings.FREEDEC_FERNET_KEY.
        - Estado inicial del ciclo de vida (is_consumed=False).
        """
        uploaded = SimpleUploadedFile("secret.pdf", self.test_content)
        emails = ["Alice@Example.COM", "  bob@domain.org "]

        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=emails,
        )

        self.assertEqual(doc.file_hash, self.expected_sha256)
        self.assertTrue(doc.encrypted_file_hash)
        self.assertFalse(doc.is_consumed)
        self.assertIsNone(doc.consumed_by)
        self.assertIsNone(doc.consumed_at)

        # Verificar normalización de emails
        self.assertIn("alice@example.com", doc.allowed_emails)
        self.assertIn("bob@domain.org", doc.allowed_emails)

        # Verificar sobres digitales para cada usuario
        self.assertIn("alice@example.com", doc.user_envelopes)
        self.assertIn("bob@domain.org", doc.user_envelopes)

        # Desempaquetar el sobre de Alice y verificar que recupera la DEK y el contenido original
        alice_env = doc.user_envelopes["alice@example.com"]
        alice_user_secret = self.crypto_service.decrypt_bytes(alice_env["encrypted_user_secret"].encode("utf-8"))
        alice_dek = Fernet(alice_user_secret).decrypt(alice_env["encrypted_dek"].encode("utf-8"))

        doc.encrypted_file.seek(0)
        enc_bytes = doc.encrypted_file.read()
        recovered_original = Fernet(alice_dek).decrypt(enc_bytes)
        self.assertEqual(recovered_original, self.test_content)

        # Desempaquetar la clave administrativa (admin_encrypted_dek)
        admin_dek = self.crypto_service.decrypt_bytes(doc.admin_encrypted_dek.encode("utf-8"))
        self.assertEqual(admin_dek, alice_dek)

    def test_upload_same_file_multiple_times_allowed(self):
        """
        Verifica que subir dos o más veces el mismo archivo está permitido,
        generando registros independientes con DEKs distintas y sobres propios.
        """
        uploaded1 = SimpleUploadedFile("contrato.pdf", self.test_content)
        doc1, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded1,
            allowed_emails=["alice@empresa.com"],
        )

        uploaded2 = SimpleUploadedFile("contrato.pdf", self.test_content)
        doc2, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded2,
            allowed_emails=["bob@empresa.com"],
        )

        self.assertNotEqual(doc1.pk, doc2.pk)
        self.assertEqual(doc1.file_hash, doc2.file_hash)
        self.assertNotEqual(doc1.encrypted_file_hash, doc2.encrypted_file_hash)
        self.assertNotEqual(doc1.admin_encrypted_dek, doc2.admin_encrypted_dek)
        self.assertIn("alice@empresa.com", doc1.user_envelopes)
        self.assertIn("bob@empresa.com", doc2.user_envelopes)

    # --------------------------------------------------------------------------
    # FLUJO DE SOLICITUD DE ACCESO (MAGIC LINK / OTP)
    # --------------------------------------------------------------------------
    def test_request_document_access_success_with_original_file(self):
        """Verifica que subir el documento original genera un token de 15 min y envía Magic Link + OTP."""
        uploaded = SimpleUploadedFile("secret.pdf", self.test_content)
        emails = ["recipient@security.org"]

        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=emails,
        )

        user_copy = SimpleUploadedFile("local_copy.pdf", self.test_content)
        success, message = self.doc_service.request_document_access(
            uploaded_file=user_copy,
            recipient_email="Recipient@Security.ORG",
            client_ip="192.168.1.10",
        )

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        sent_email = mail.outbox[0]
        self.assertIn("recipient@security.org", sent_email.to)
        self.assertIn("secret.pdf", sent_email.subject)
        self.assertIn("/freedec/consumir/?t=", sent_email.body)
        self.assertIn("CÓDIGO OTP:", sent_email.body)

        # Verificar creación del token en BD
        token_obj = AccessVerificationToken.objects.filter(document=doc, email="recipient@security.org").first()
        self.assertIsNotNone(token_obj)
        self.assertFalse(token_obj.is_used)
        self.assertEqual(len(token_obj.otp_code), 6)
        self.assertTrue(token_obj.otp_code.isdigit())
        self.assertTrue(token_obj.is_valid())

        # Verificar auditoría
        log = DocumentAccessLog.objects.filter(document=doc, action="solicitud_acceso").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.email, "recipient@security.org")
        self.assertEqual(log.ip_address, "192.168.1.10")

    def test_request_document_access_success_with_enc_file(self):
        """Verifica que un usuario pueda subir el archivo .enc para solicitar acceso."""
        uploaded = SimpleUploadedFile("secret_enc.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["client@company.com"],
        )

        doc.encrypted_file.seek(0)
        enc_file_obj = SimpleUploadedFile("distributed.enc", doc.encrypted_file.read())

        success, _ = self.doc_service.request_document_access(
            uploaded_file=enc_file_obj,
            recipient_email="client@company.com",
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("client@company.com", mail.outbox[0].to)

    def test_request_document_access_anti_enumeration(self):
        """Verifica respuesta neutra sin envíos de correo para archivos o emails no autorizados."""
        fake_pdf = SimpleUploadedFile("unknown.pdf", b"%PDF-1.4\n1 0 obj<</Unknown>>endobj\nxref\n0 0\n")
        success, _ = self.doc_service.request_document_access(
            uploaded_file=fake_pdf,
            recipient_email="intruder@external.com",
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 0)

    def test_access_token_model_methods_and_expiration(self):
        """Verifica los métodos is_expired() e is_valid() con límite estricto de 15 minutos."""
        uploaded = SimpleUploadedFile("token_test.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["test@token.local"],
        )

        token = AccessVerificationToken.objects.create(
            document=doc,
            email="test@token.local",
            token_hash="samplehash123",
            otp_code="123456",
            expires_at=timezone.now() + timezone.timedelta(minutes=15),
            is_used=False,
        )
        self.assertFalse(token.is_expired())
        self.assertTrue(token.is_valid())

        # Expiración
        token.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        self.assertTrue(token.is_expired())
        self.assertFalse(token.is_valid())

    # --------------------------------------------------------------------------
    # CONSUMO Y DESTRUCCIÓN FÍSICA (BURN-AFTER-READ)
    # --------------------------------------------------------------------------
    def test_consume_and_burn_via_magic_link_token(self):
        """
        Verifica el ciclo completo de consumo mediante token de Magic Link:
        - Descifra el contenido original en memoria.
        - Destruye físicamente el archivo .enc de disco (save=False).
        - Actualiza el documento como consumido (is_consumed=True, consumed_by, consumed_at).
        - Marca el token como usado.
        - Registra action='descifrado_completado_burn' en DocumentAccessLog.
        """
        uploaded = SimpleUploadedFile("burn_target.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["authorized@burn.org"],
        )
        storage = doc.encrypted_file.storage
        file_path = doc.encrypted_file.name
        self.assertTrue(storage.exists(file_path))

        # Solicitar acceso para obtener token
        doc.encrypted_file.seek(0)
        enc_copy = SimpleUploadedFile("burn_target.enc", doc.encrypted_file.read())
        self.doc_service.request_document_access(
            uploaded_file=enc_copy,
            recipient_email="authorized@burn.org",
            client_ip="10.0.0.5",
            user_agent="SecurityTester/1.0",
        )

        sent_body = mail.outbox[-1].body
        # Extraer token urlsafe de la URL en el correo: ?t=...
        token_str = sent_body.split("?t=")[1].split()[0]

        # Consumir documento
        success, decrypted_bytes, filename, mimetype, message = (
            self.doc_service.consume_and_burn_document(
                token_str=token_str,
                client_ip="10.0.0.5",
                user_agent="SecurityTester/1.0",
            )
        )

        self.assertTrue(success)
        self.assertEqual(decrypted_bytes, self.test_content)
        self.assertEqual(filename, "burn_target.pdf")
        self.assertEqual(mimetype, "application/pdf")

        # Comprobar DESTRUCCIÓN FÍSICA en disco
        self.assertFalse(storage.exists(file_path))

        # Comprobar estado en base de datos
        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)
        self.assertEqual(doc.consumed_by, "authorized@burn.org")
        self.assertIsNotNone(doc.consumed_at)
        self.assertEqual(doc.access_count, 1)
        self.assertEqual(doc.last_accessed_by, "authorized@burn.org")

        # Comprobar token marcado como usado
        token_obj = AccessVerificationToken.objects.filter(document=doc).first()
        self.assertTrue(token_obj.is_used)

        # Comprobar log de auditoría
        burn_log = DocumentAccessLog.objects.filter(
            document=doc,
            action="descifrado_completado_burn",
        ).first()
        self.assertIsNotNone(burn_log)
        self.assertEqual(burn_log.email, "authorized@burn.org")
        self.assertEqual(burn_log.ip_address, "10.0.0.5")

    def test_consume_and_burn_via_otp_code(self):
        """Verifica el consumo y destrucción física mediante código numérico OTP de 6 dígitos."""
        uploaded = SimpleUploadedFile("otp_burn.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["otp_user@company.com"],
        )
        storage = doc.encrypted_file.storage
        file_path = doc.encrypted_file.name

        doc.encrypted_file.seek(0)
        enc_copy = SimpleUploadedFile("otp_burn.enc", doc.encrypted_file.read())
        self.doc_service.request_document_access(
            uploaded_file=enc_copy,
            recipient_email="otp_user@company.com",
        )

        token_obj = AccessVerificationToken.objects.filter(document=doc).first()
        otp = token_obj.otp_code

        success, decrypted_bytes, filename, mimetype, message = (
            self.doc_service.consume_and_burn_document(
                otp_code=otp,
                email="otp_user@company.com",
            )
        )

        self.assertTrue(success)
        self.assertEqual(decrypted_bytes, self.test_content)
        self.assertFalse(storage.exists(file_path))

        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed)
        self.assertEqual(doc.consumed_by, "otp_user@company.com")

    def test_consume_rejects_used_or_expired_token(self):
        """Un token ya utilizado o expirado debe ser rechazado sin entregar datos ni destruir archivos."""
        uploaded = SimpleUploadedFile("reject_token.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["valid@test.local"],
        )

        doc.encrypted_file.seek(0)
        enc_copy = SimpleUploadedFile("doc.enc", doc.encrypted_file.read())
        self.doc_service.request_document_access(
            uploaded_file=enc_copy,
            recipient_email="valid@test.local",
        )
        token_str = mail.outbox[-1].body.split("?t=")[1].split()[0]

        token_obj = AccessVerificationToken.objects.filter(document=doc).first()
        token_obj.expires_at = timezone.now() - timezone.timedelta(minutes=1)
        token_obj.save(update_fields=["expires_at"])

        success, decrypted, _, _, msg = self.doc_service.consume_and_burn_document(token_str=token_str)
        self.assertFalse(success)
        self.assertIsNone(decrypted)
        self.assertIn("expirado", msg.lower())

        # Probar token ya usado
        token_obj.expires_at = timezone.now() + timezone.timedelta(minutes=15)
        token_obj.is_used = True
        token_obj.save(update_fields=["expires_at", "is_used"])

        success, decrypted, _, _, msg = self.doc_service.consume_and_burn_document(token_str=token_str)
        self.assertFalse(success)
        self.assertIsNone(decrypted)
        self.assertIn("utilizado", msg.lower())

    # --------------------------------------------------------------------------
    # GESTIÓN DE ACCESOS POSTERIORES (ARCHIVO YA CONSUMIDO)
    # --------------------------------------------------------------------------
    def test_post_consumption_notification_and_audit(self):
        """
        Si otro usuario autorizado solicita acceso a un documento ya consumido:
        - No produce error 500 ni fuga datos.
        - Envía un correo notificando que fue retirado por {consumed_by} en {consumed_at}.
        - Registra action='intento_post_consumo' en DocumentAccessLog.
        """
        uploaded = SimpleUploadedFile("acuerdo.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["primero@empresa.com", "segundo@empresa.com"],
        )

        # Consumo por el primer usuario
        doc.encrypted_file.seek(0)
        enc_bytes = doc.encrypted_file.read()
        self.doc_service.request_document_access(
            uploaded_file=SimpleUploadedFile("acuerdo.enc", enc_bytes),
            recipient_email="primero@empresa.com",
        )
        token_str = mail.outbox[-1].body.split("?t=")[1].split()[0]
        self.doc_service.consume_and_burn_document(token_str=token_str)

        mail.outbox.clear()

        # Segundo usuario intenta solicitar acceso con el archivo .enc
        success, message = self.doc_service.request_document_access(
            uploaded_file=SimpleUploadedFile("acuerdo.enc", enc_bytes),
            recipient_email="segundo@empresa.com",
            client_ip="198.51.100.22",
        )
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        post_mail = mail.outbox[0]
        self.assertIn("segundo@empresa.com", post_mail.to)
        self.assertIn("[Freedec] Archivo ya retirado: acuerdo.pdf", post_mail.subject)
        self.assertIn("El documento 'acuerdo.pdf' ya fue retirado por primero@empresa.com", post_mail.body)
        self.assertIn("Solicite una copia directamente a esa dirección.", post_mail.body)

        # Verificar auditoría
        post_log = DocumentAccessLog.objects.filter(
            document=doc,
            action="intento_post_consumo",
        ).first()
        self.assertIsNotNone(post_log)
        self.assertEqual(post_log.email, "segundo@empresa.com")
        self.assertEqual(post_log.ip_address, "198.51.100.22")

    # --------------------------------------------------------------------------
    # ACCESO ADMINISTRATIVO SIN DESTRUCCIÓN (AUDIT BYPASS)
    # --------------------------------------------------------------------------
    def test_admin_decrypt_preserves_file_and_audit_bypass(self):
        """
        Un administrador autenticado descarga el archivo original sin destruirlo ni marcarlo consumido.
        Registra action='admin_inspeccion_preservada' en DocumentAccessLog.
        """
        uploaded = SimpleUploadedFile("informe_confidencial.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["auditor@seguridad.local"],
        )
        storage = doc.encrypted_file.storage
        file_path = doc.encrypted_file.name

        success, decrypted_bytes, filename, mimetype, message = (
            self.doc_service.admin_decrypt_document(
                document=doc,
                admin_user=self.admin_user,
                client_ip="10.200.1.1",
            )
        )

        self.assertTrue(success)
        self.assertEqual(decrypted_bytes, self.test_content)
        self.assertEqual(filename, "informe_confidencial.pdf")

        # PRESERVACIÓN: El archivo sigue en disco y no está consumido
        self.assertTrue(storage.exists(file_path))
        doc.refresh_from_db()
        self.assertFalse(doc.is_consumed)

        # AUDITORÍA ADMINISTRATIVA
        admin_log = DocumentAccessLog.objects.filter(
            document=doc,
            action="admin_inspeccion_preservada",
        ).first()
        self.assertIsNotNone(admin_log)
        self.assertEqual(admin_log.email, self.admin_user.email)
        self.assertEqual(admin_log.ip_address, "10.200.1.1")

    def test_admin_decrypt_fails_if_document_already_consumed(self):
        """Si el documento ya fue consumido por un usuario final, el admin no puede descargarlo."""
        uploaded = SimpleUploadedFile("consumed_report.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["user@test.local"],
        )
        doc.encrypted_file.seek(0)
        self.doc_service.request_document_access(
            uploaded_file=SimpleUploadedFile("consumed_report.enc", doc.encrypted_file.read()),
            recipient_email="user@test.local",
        )
        token_str = mail.outbox[-1].body.split("?t=")[1].split()[0]
        self.doc_service.consume_and_burn_document(token_str=token_str)

        doc.refresh_from_db()
        success, decrypted, _, _, msg = self.doc_service.admin_decrypt_document(
            document=doc,
            admin_user=self.admin_user,
        )
        self.assertFalse(success)
        self.assertIsNone(decrypted)
        self.assertIn("ya fue consumido", msg)

    # --------------------------------------------------------------------------
    # BORRADO FÍSICO POR SEÑALES DEL MODELO
    # --------------------------------------------------------------------------
    def test_file_renaming_does_not_affect_hash(self):
        """Demuestra que renombrar el archivo no altera el hash SHA-256 ni la verificación."""
        file1 = SimpleUploadedFile("nombre_original_del_archivo.pdf", self.test_content)
        file2 = SimpleUploadedFile("nombre_completamente_cambiado_por_usuario.pdf", self.test_content)
        hash1 = calculate_file_sha256(file1)
        hash2 = calculate_file_sha256(file2)
        self.assertEqual(hash1, hash2)

    def test_original_filename_and_enc_naming(self):
        """El registro guarda el nombre original y el archivo cifrado preserva el nombre con sufijo .enc."""
        uploaded = SimpleUploadedFile("balance_anual_2026.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["finance@test.local"],
        )
        self.assertEqual(doc.original_filename, "balance_anual_2026.pdf")
        self.assertIn("balance_anual_2026.pdf", doc.encrypted_file.name)
        self.assertTrue(doc.encrypted_file.name.endswith(".enc"))

    def test_physical_file_deleted_on_model_delete(self):
        """Verifica que al eliminar un modelo EncryptedDocument no consumido se borra el archivo físico."""
        uploaded = SimpleUploadedFile("file_to_delete.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["del@test.local"],
        )
        storage = doc.encrypted_file.storage
        file_name = doc.encrypted_file.name
        self.assertTrue(storage.exists(file_name))

        doc.delete()
        self.assertFalse(storage.exists(file_name))

    def test_physical_file_deleted_on_queryset_delete(self):
        """Verifica que al eliminar mediante QuerySet.delete() se borra el archivo físico."""
        uploaded = SimpleUploadedFile("bulk_delete.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["bulk@test.local"],
        )
        storage = doc.encrypted_file.storage
        file_name = doc.encrypted_file.name
        self.assertTrue(storage.exists(file_name))

        EncryptedDocument.objects.filter(id=doc.id).delete()
        self.assertFalse(storage.exists(file_name))

    def test_burn_policy_all_recipients_lifecycle(self):
        """
        Verifica el ciclo de vida completo de la política ALL_RECIPIENTS:
        1. Se sube documento para Alice y Bob con burn_policy='ALL_RECIPIENTS'.
        2. Alice solicita acceso y consume el documento.
        3. El archivo físico se PRESERVA en disco y el documento NO se marca como consumido.
        4. Alice intenta volver a acceder y es notificada de que ya descargó su copia.
        5. Bob solicita acceso y consume el documento.
        6. Al ser el último destinatario, el archivo físico se ELIMINA y el documento se marca consumido.
        """
        uploaded = SimpleUploadedFile("balance_multi.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["alice@empresa.com", "bob@empresa.com"],
            burn_policy=EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
        )
        self.assertEqual(doc.burn_policy, EncryptedDocument.BurnPolicy.ALL_RECIPIENTS)
        self.assertEqual(doc.consumed_recipients, [])
        self.assertFalse(doc.is_consumed)

        storage = doc.encrypted_file.storage
        file_name = doc.encrypted_file.name
        self.assertTrue(storage.exists(file_name))

        doc.encrypted_file.seek(0)
        enc_bytes = doc.encrypted_file.read()

        # 1. Alice solicita acceso
        mail.outbox.clear()
        self.doc_service.request_document_access(
            uploaded_file=SimpleUploadedFile("balance_multi.enc", enc_bytes),
            recipient_email="alice@empresa.com",
        )
        self.assertEqual(len(mail.outbox), 1)
        alice_token_str = mail.outbox[0].body.split("?t=")[1].split()[0]

        # Alice consume el documento
        success, decrypted_bytes, suggested_filename, mimetype, msg = (
            self.doc_service.consume_and_burn_document(token_str=alice_token_str)
        )
        self.assertTrue(success)
        self.assertEqual(decrypted_bytes, self.test_content)

        doc.refresh_from_db()
        self.assertFalse(doc.is_consumed, "El documento NO debe estar consumido porque Bob aún no accedió")
        self.assertTrue(storage.exists(file_name), "El archivo físico DEBE preservarse para Bob")
        self.assertIn("alice@empresa.com", doc.consumed_recipients)
        self.assertNotIn("bob@empresa.com", doc.consumed_recipients)

        # Verificar log de descifrado parcial
        log_alice = DocumentAccessLog.objects.filter(
            document=doc,
            email="alice@empresa.com",
            action="descifrado_parcial_preservado",
        ).first()
        self.assertIsNotNone(log_alice)

        # 2. Alice intenta solicitar acceso nuevamente
        mail.outbox.clear()
        self.doc_service.request_document_access(
            uploaded_file=SimpleUploadedFile("balance_multi.enc", enc_bytes),
            recipient_email="alice@empresa.com",
        )
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Copia ya descargada", mail.outbox[0].subject)

        # 3. Bob solicita acceso
        mail.outbox.clear()
        self.doc_service.request_document_access(
            uploaded_file=SimpleUploadedFile("balance_multi.enc", enc_bytes),
            recipient_email="bob@empresa.com",
        )
        self.assertEqual(len(mail.outbox), 1)
        bob_token_str = mail.outbox[0].body.split("?t=")[1].split()[0]

        # Bob consume el documento (es el último)
        success_bob, decrypted_bob, _, _, _ = (
            self.doc_service.consume_and_burn_document(token_str=bob_token_str)
        )
        self.assertTrue(success_bob)
        self.assertEqual(decrypted_bob, self.test_content)

        doc.refresh_from_db()
        self.assertTrue(doc.is_consumed, "El documento AHORA debe estar consumido por completarse todos")
        self.assertFalse(storage.exists(file_name), "El archivo físico DEBE haber sido eliminado del disco")
        self.assertIn("alice@empresa.com", doc.consumed_recipients)
        self.assertIn("bob@empresa.com", doc.consumed_recipients)

        # Verificar log de descifrado final burn
        log_bob = DocumentAccessLog.objects.filter(
            document=doc,
            email="bob@empresa.com",
            action="descifrado_completado_burn",
        ).first()
        self.assertIsNotNone(log_bob)

    def test_reactivate_document_replaces_emails_and_preserves_history(self):
        """
        Verifica que reactivate_document:
        1. Re-cifra el archivo con nueva DEK y crea nuevo archivo en disco.
        2. Reemplaza allowed_emails exclusivamente con los nuevos correos (los anteriores no permanecen).
        3. Reconstruye user_envelopes solo para los nuevos correos.
        4. Resetea is_consumed a False y consumed_recipients a [].
        5. Preserva el registro histórico en DocumentAccessLog con detalles de destinatarios anteriores y nuevos.
        """
        uploaded = SimpleUploadedFile("balance_reactivar.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["antiguo1@empresa.com", "antiguo2@empresa.com"],
        )
        old_dek = doc.admin_encrypted_dek
        old_hash = doc.encrypted_file_hash

        # Simular consumo previo
        doc.is_consumed = True
        doc.consumed_by = "antiguo1@empresa.com"
        doc.consumed_recipients = ["antiguo1@empresa.com"]
        doc.encrypted_file.delete(save=False)
        doc.save()

        # Reactivar con nuevos destinatarios
        reupload_file = SimpleUploadedFile("balance_reactivar.pdf", self.test_content)
        reactivated = self.doc_service.reactivate_document(
            document=doc,
            original_file=reupload_file,
            new_emails=["nuevo1@empresa.com", "nuevo2@empresa.com"],
            admin_user=self.admin_user,
        )

        self.assertEqual(reactivated.pk, doc.pk)
        self.assertFalse(reactivated.is_consumed)
        self.assertEqual(reactivated.consumed_recipients, [])
        self.assertIsNone(reactivated.consumed_by)
        self.assertNotEqual(reactivated.admin_encrypted_dek, old_dek)
        self.assertNotEqual(reactivated.encrypted_file_hash, old_hash)

        # Los correos antiguos ya NO están en la lista, solo los nuevos
        self.assertNotIn("antiguo1@empresa.com", reactivated.allowed_emails)
        self.assertNotIn("antiguo2@empresa.com", reactivated.allowed_emails)
        self.assertIn("nuevo1@empresa.com", reactivated.allowed_emails)
        self.assertIn("nuevo2@empresa.com", reactivated.allowed_emails)
        self.assertIn("nuevo1@empresa.com", reactivated.user_envelopes)
        self.assertNotIn("antiguo1@empresa.com", reactivated.user_envelopes)

        # Archivo físico en disco restaurado
        self.assertTrue(reactivated.encrypted_file.storage.exists(reactivated.encrypted_file.name))

        # Log histórico de reactivación registrado
        log = DocumentAccessLog.objects.filter(
            document=reactivated,
            action="reactivacion_documento",
        ).first()
        self.assertIsNotNone(log)
        self.assertIn("antiguo1@empresa.com", log.user_agent)
        self.assertIn("nuevo1@empresa.com", log.user_agent)

    def test_reactivate_document_rejects_mismatched_hash(self):
        """Reactivar con un archivo de contenido diferente arroja ValidationError."""
        uploaded = SimpleUploadedFile("original.pdf", self.test_content)
        doc, _ = self.doc_service.upload_and_encrypt_document(
            original_file=uploaded,
            allowed_emails=["test@empresa.com"],
        )
        different_file = SimpleUploadedFile("otro.pdf", b"%PDF-1.4 completely different content")
        with self.assertRaises(ValidationError):
            self.doc_service.reactivate_document(
                document=doc,
                original_file=different_file,
                new_emails=["nuevo@empresa.com"],
            )

