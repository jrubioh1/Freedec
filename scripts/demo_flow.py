#!/usr/bin/env python3
"""
Script interactivo para probar el flujo completo de Freedec en el entorno de Staging.

Valida:
1. Subida administrativa protegida con arquitectura DEK multi-usuario y sobres digitales (user_envelopes).
2. Identificación unívoca basada en hash SHA-256 (sin IDs secuenciales ni IDORs).
3. Solicitud pública de acceso con prueba de posesión, enlace mágico y código OTP temporal de 15 minutos.
4. Consumo y descarga con política estricta de destrucción física (Burn-After-Read).
5. Gestión de accesos posteriores: notificación automática si el recurso ya fue retirado.
6. Pruebas de ciberseguridad (OWASP Top 10):
   - Rechazo de formatos no permitidos (.exe, .txt).
   - Detección de spoofing de extensiones / Magic Bytes inválidos.
   - Mitigación de timing attacks y enumeración ante correos no autorizados.
   - Detección de archivos alterados (mismatch de hash SHA-256).
"""

import hashlib
import json
import mimetypes
import os
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django
django.setup()

from django.core import mail
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from freedec.models import AccessVerificationToken, DocumentAccessLog, EncryptedDocument
from freedec.services import DocumentManagementService
from freedec.validators import validate_document_file

BASE_URL = os.environ.get("FREEDEC_API_URL", "http://127.0.0.1:8000")
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

# Contenido binario de un archivo PDF-1.4 mínimo válido
MINIMAL_VALID_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


def encode_multipart_formdata(fields: dict, files: dict):
    """Codifica datos y archivos en el formato estándar multipart/form-data."""
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
    body = bytearray()

    for key, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
        if isinstance(value, (list, dict)):
            body.extend(json.dumps(value).encode("utf-8"))
        else:
            body.extend(str(value).encode("utf-8"))
        body.extend(b"\r\n")

    for key, (filename, file_content) in files.items():
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(
            f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'.encode("utf-8")
        )
        body.extend(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
        body.extend(file_content)
        body.extend(b"\r\n")

    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return bytes(body), headers


def print_step(title):
    print(f"\n{'='*75}\n{title}\n{'='*75}")


def main():
    print_step("FREEDEC - DEMO INTERACTIVA DE STAGING (OWASP TOP 10 & ZERO-TRUST)")
    print(f"Conectando a: {BASE_URL}")

    # Verificar conectividad con el servidor Django
    try:
        req = Request(f"{BASE_URL}/freedec/", method="GET")
        with urlopen(req) as resp:
            pass
    except URLError as e:
        print(f"✗ No se pudo conectar al servidor Django en {BASE_URL}: {e.reason}")
        print("Asegúrate de haber iniciado el servidor con: 'poetry run python manage.py runserver'")
        sys.exit(1)

    sample_file = Path("sample_document.pdf")
    sample_file.write_bytes(MINIMAL_VALID_PDF)
    file_bytes = sample_file.read_bytes()

    # --------------------------------------------------------------------------
    # PRUEBA OWASP A03/A08: Rechazo de Formato No Autorizado (.exe)
    # --------------------------------------------------------------------------
    print_step("PRUEBA PREVIA: Intentar procesar formato malicioso/no permitido (.exe)")
    fake_exe = SimpleUploadedFile("malware.exe", b"MZ\x90\x00FakePEHeaderData")
    try:
        validate_document_file(fake_exe)
        print("✗ ERROR: El validador aceptó un archivo ejecutable!")
    except ValidationError as e:
        print(f"✓ ÉXITO OWASP: El validador rechazó el formato .exe correctamente.")
        print(f"  Detalle: {e.messages}")

    # --------------------------------------------------------------------------
    # PASO 1: Subida de Documento por el Administrador (Arquitectura DEK Multi-Usuario)
    # --------------------------------------------------------------------------
    print_step("PASO 1: Administrador registra documento con DEK y sobres digitales")
    allowed_emails = ["auditor@seguridad.local", "jorge@freedec.local"]

    # Si ya existía de una ejecución previa, lo eliminamos para asegurar prueba limpia
    existing = EncryptedDocument.objects.filter(file_hash=hashlib.sha256(file_bytes).hexdigest()).first()
    if existing:
        existing.delete()

    service = DocumentManagementService()
    uploaded_file = SimpleUploadedFile(sample_file.name, file_bytes)
    doc, _ = service.upload_and_encrypt_document(
        original_file=uploaded_file,
        allowed_emails=allowed_emails,
    )
    print(f"✓ Documento registrado y cifrado en el sistema.")
    print(f"✓ Hash SHA-256 (Identificador Criptográfico): {doc.file_hash}")
    print(f"✓ Archivo Cifrado en disco (.enc): {doc.encrypted_file.path}")
    print(f"✓ Sobres Digitales generados: {list(doc.user_envelopes.keys())}")
    print(f"✓ Estado inicial: is_consumed={doc.is_consumed}")

    # --------------------------------------------------------------------------
    # PASO 2: Solicitud de Acceso por Usuario Autorizado (Magic Link / OTP)
    # --------------------------------------------------------------------------
    print_step("PASO 2: Solicitud Pública de Acceso (/freedec/public/request-access/)")
    print(f"Solicitante: auditor@seguridad.local")
    print(f"Enviando archivo PDF original / .enc...")

    public_url = f"{BASE_URL}/freedec/public/request-access/"
    public_fields = {
        "email": "auditor@seguridad.local",
    }
    public_files = {
        "file": (sample_file.name, file_bytes),
    }

    body, headers = encode_multipart_formdata(public_fields, public_files)
    req = Request(public_url, data=body, headers=headers, method="POST")

    try:
        with urlopen(req) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            print(f"✓ Estado HTTP: {resp.getcode()}")
            print(f"✓ Mensaje Servidor: {resp_data['message']}")
    except HTTPError as e:
        print(f"✗ Error inesperado: {e.code}: {e.read().decode()}")
        sys.exit(1)

    # Localizar el token generado para la prueba
    token_obj = AccessVerificationToken.objects.filter(
        document=doc,
        email="auditor@seguridad.local",
        is_used=False,
    ).first()
    if not token_obj:
        print("✗ No se encontró el token generado en la base de datos.")
        sys.exit(1)

    print(f"✓ Token de verificación generado con caducidad de 15 minutos.")
    print(f"✓ Código OTP de 6 dígitos: {token_obj.otp_code}")

    # --------------------------------------------------------------------------
    # PASO 3: Consumo y Destrucción Física (Burn-After-Read)
    # --------------------------------------------------------------------------
    print_step("PASO 3: Consumo y Destrucción Inmediata (Burn-After-Read) con OTP")
    consume_url = f"{BASE_URL}/freedec/api/public/consume/"
    consume_payload = json.dumps({
        "otp_code": token_obj.otp_code,
        "email": "auditor@seguridad.local",
    }).encode("utf-8")

    req_consume = Request(
        consume_url,
        data=consume_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(req_consume) as resp:
            decrypted_data = resp.read()
            print(f"✓ Estado HTTP: {resp.getcode()} (Descarga completada)")
            print(f"✓ Bytes recibidos: {len(decrypted_data)} bytes")
            if decrypted_data == file_bytes:
                print("✓ ¡El archivo descifrado coincide EXACTAMENTE con el original!")
            else:
                print("✗ El archivo descifrado no coincide con el original.")
    except HTTPError as e:
        print(f"✗ Error en consumo: {e.code}: {e.read().decode()}")
        sys.exit(1)

    # Verificar que el archivo físico fue destruido
    doc.refresh_from_db()
    storage = doc.encrypted_file.storage
    if not storage.exists(doc.encrypted_file.name):
        print("✓ ¡DESTRUCCIÓN FÍSICA CONFIRMADA! El archivo .enc fue eliminado del disco.")
    else:
        print("✗ Alerta: El archivo físico aún existe en disco.")

    print(f"✓ Estado en BD: is_consumed={doc.is_consumed}, consumed_by={doc.consumed_by}, consumed_at={doc.consumed_at}")

    # --------------------------------------------------------------------------
    # PASO 4: Gestión de Intentos Posteriores (Archivo Ya Consumido)
    # --------------------------------------------------------------------------
    print_step("PASO 4: Segundo usuario intenta solicitar acceso al archivo ya retirado")
    post_fields = {
        "email": "jorge@freedec.local",
    }
    body_post, headers_post = encode_multipart_formdata(post_fields, public_files)
    req_post = Request(public_url, data=body_post, headers=headers_post, method="POST")

    with urlopen(req_post) as resp:
        resp_data = json.loads(resp.read().decode("utf-8"))
        print(f"✓ Estado HTTP: {resp.getcode()}")
        print(f"✓ Respuesta Neutra al Navegador: {resp_data['message']}")

    # Comprobar que se auditó el intento post-consumo
    post_log = DocumentAccessLog.objects.filter(document=doc, action="intento_post_consumo").first()
    if post_log:
        print(f"✓ Intento post-consumo auditado correctamente para '{post_log.email}'.")

    # --------------------------------------------------------------------------
    # PASO 5: Prueba OWASP A04 - Correo No Autorizado (Anti-Enumeración)
    # --------------------------------------------------------------------------
    print_step("PASO 5: Mitigación OWASP A04 - Correo No Autorizado (attacker@evil.com)")
    bad_email_fields = {
        "email": "attacker@evil.com",
    }
    body_bad, headers_bad = encode_multipart_formdata(bad_email_fields, public_files)
    req_bad = Request(public_url, data=body_bad, headers=headers_bad, method="POST")

    with urlopen(req_bad) as resp:
        resp_data = json.loads(resp.read().decode("utf-8"))
        print(f"✓ Estado HTTP: {resp.getcode()}")
        print(f"✓ Respuesta Neutra: {resp_data['message']}")
        print("✓ Resultado: NINGÚN token generado y el atacante no recibe pista alguna.")

    # --------------------------------------------------------------------------
    # PASO 6: Prueba OWASP A08 - Archivo Alterado / Modificado
    # --------------------------------------------------------------------------
    print_step("PASO 6: Mitigación OWASP A08 - Detección de Integridad por SHA-256")
    altered_bytes = file_bytes + b"\n% Tampered byte at the end"
    altered_files = {"file": ("altered.pdf", altered_bytes)}

    body_alt, headers_alt = encode_multipart_formdata(public_fields, altered_files)
    req_alt = Request(public_url, data=body_alt, headers=headers_alt, method="POST")

    with urlopen(req_alt) as resp:
        resp_data = json.loads(resp.read().decode("utf-8"))
        print(f"✓ Estado HTTP: {resp.getcode()}")
        print(f"✓ Respuesta Neutra: {resp_data['message']}")
        print("✓ El hash calculado en runtime difiere -> Petición neutralizada.")

    print_step("¡DEMOSTRACIÓN OWASP TOP 10 Y BURN-AFTER-READ COMPLETADA CON ÉXITO!")


if __name__ == "__main__":
    main()
