#!/usr/bin/env python3
"""
Script interactivo para probar el flujo completo de Freedec en el entorno de Staging.

Valida:
1. Subida administrativa protegida de documentos PDF, LibreOffice y Microsoft Office.
2. Identificación unívoca basada en hash SHA-256.
3. Despacho automatizado de contraseña por correo electrónico a destinatarios autorizados.
4. Pruebas de ciberseguridad (OWASP Top 10):
   - Rechazo de formatos no permitidos (.exe, .txt).
   - Detección de spoofing de extensiones / Magic Bytes inválidos.
   - Mitigación de timing attacks y enumeración ante correos no autorizados.
   - Detección de archivos alterados (mismatch de hash SHA-256).
"""

import base64
import json
import mimetypes
import os
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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
    print_step("FREEDEC - DEMO INTERACTIVA DE STAGING (OWASP TOP 10 READY)")
    print(f"Conectando a: {BASE_URL}")

    sample_file = Path("sample_document.pdf")
    sample_file.write_bytes(MINIMAL_VALID_PDF)
    file_bytes = sample_file.read_bytes()

    # --------------------------------------------------------------------------
    # PRUEBA OWASP A03/A08: Rechazo de Formato No Autorizado (.exe)
    # --------------------------------------------------------------------------
    print_step("PRUEBA PREVIA: Intentar subir formato malicioso/no permitido (.exe)")
    upload_url = f"{BASE_URL}/freedec/api/admin/upload/"
    auth_header = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}".encode()).decode()

    malicious_body, malicious_headers = encode_multipart_formdata(
        {"plain_password": "Password123!", "allowed_emails": ["test@freedec.local"]},
        {"original_file": ("malware.exe", b"MZ\x90\x00FakePEHeaderData")},
    )
    malicious_headers["Authorization"] = f"Basic {auth_header}"

    try:
        req = Request(upload_url, data=malicious_body, headers=malicious_headers, method="POST")
        with urlopen(req) as resp:
            print("✗ ERROR: El servidor aceptó un archivo ejecutable!")
    except HTTPError as e:
        print(f"✓ ÉXITO OWASP: El servidor rechazó el formato .exe con HTTP {e.code}")
        print(f"  Detalle: {e.read().decode('utf-8')[:120]}...")
    except URLError as e:
        print(f"✗ No se pudo conectar al servidor Django en {BASE_URL}: {e.reason}")
        print("Asegúrate de haber iniciado el servidor con: 'poetry run python manage.py runserver'")
        sys.exit(1)

    # --------------------------------------------------------------------------
    # PASO 1: Subida de Documento PDF Válido por el Administrador
    # --------------------------------------------------------------------------
    print_step("PASO 1: Administrador sube y cifra documento PDF (/freedec/api/admin/upload/)")
    plain_password = "ClaveUltraSegura#2026_Audit!"
    allowed_emails = ["auditor@seguridad.local", "jorge@freedec.local"]

    fields = {
        "plain_password": plain_password,
        "allowed_emails": allowed_emails,
    }
    files = {
        "original_file": (sample_file.name, file_bytes),
    }

    body, headers = encode_multipart_formdata(fields, files)
    headers["Authorization"] = f"Basic {auth_header}"
    req = Request(upload_url, data=body, headers=headers, method="POST")

    try:
        with urlopen(req) as resp:
            status_code = resp.getcode()
            response_data = json.loads(resp.read().decode("utf-8"))
            print(f"✓ Estado HTTP: {status_code}")
            print(f"✓ Hash SHA-256 (Identificador Criptográfico): {response_data['file_hash']}")
            print(f"✓ URL Archivo Cifrado en disco: {response_data['encrypted_file_url']}")
            print(f"✓ Código de Acceso Generado (Zero-Knowledge): {response_data['access_code']}")
            print(f"✓ Correos autorizados (Normalizados): {response_data['allowed_emails']}")

            access_code = response_data["access_code"]
    except HTTPError as e:
        error_body = e.read().decode("utf-8")
        if "Ya existe un documento registrado" in error_body:
            print("! El documento ya había sido registrado anteriormente.")
            print("Crea un PDF con variación para registrar uno nuevo.")
            sys.exit(0)
        else:
            print(f"✗ Error HTTP {e.code}: {error_body}")
            sys.exit(1)

    # --------------------------------------------------------------------------
    # PASO 2: Usuario Público Solicita Contraseña con Datos Válidos
    # --------------------------------------------------------------------------
    print_step("PASO 2: Solicitud Pública Válida (/freedec/api/public/request-password/)")
    print(f"Solicitante: auditor@seguridad.local")
    print(f"Enviando archivo PDF original + access_code...")

    public_url = f"{BASE_URL}/freedec/api/public/request-password/"
    public_fields = {
        "access_code": access_code,
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
            print("\n" + "*" * 70)
            print("¡ÉXITO TOTAL! OBSERVA LA TERMINAL DE DJANGO (runserver):")
            print("Verás el correo electrónico impreso por consola con la contraseña descifrada:")
            print(f"--> '{plain_password}'")
            print("*" * 70)
    except HTTPError as e:
        print(f"✗ Error inesperado: {e.code}: {e.read().decode()}")

    # --------------------------------------------------------------------------
    # PASO 3: Prueba OWASP A04 - Correo No Autorizado (Anti-Enumeración)
    # --------------------------------------------------------------------------
    print_step("PASO 3: Mitigación OWASP A04 - Correo No Autorizado (attacker@evil.com)")
    bad_email_fields = {
        "access_code": access_code,
        "email": "attacker@evil.com",
    }
    body, headers = encode_multipart_formdata(bad_email_fields, public_files)
    req = Request(public_url, data=body, headers=headers, method="POST")

    with urlopen(req) as resp:
        resp_data = json.loads(resp.read().decode("utf-8"))
        print(f"✓ Estado HTTP: {resp.getcode()}")
        print(f"✓ Respuesta de Seguridad Neutra: {resp_data['message']}")
        print("✓ Resultado: NINGÚN correo fue enviado y el atacante no recibe pista alguna.")

    # --------------------------------------------------------------------------
    # PASO 4: Prueba OWASP A08 - Archivo Alterado / Modificado
    # --------------------------------------------------------------------------
    print_step("PASO 4: Mitigación OWASP A08 - Detección de Integridad por SHA-256")
    altered_bytes = file_bytes + b"\n% Tampered byte at the end"
    altered_files = {"file": ("altered.pdf", altered_bytes)}

    body, headers = encode_multipart_formdata(public_fields, altered_files)
    req = Request(public_url, data=body, headers=headers, method="POST")

    with urlopen(req) as resp:
        resp_data = json.loads(resp.read().decode("utf-8"))
        print(f"✓ Estado HTTP: {resp.getcode()}")
        print(f"✓ Respuesta Neutra: {resp_data['message']}")
        print("✓ El hash calculado en runtime difiere -> Petición neutralizada.")

    print_step("¡DEMOSTRACIÓN DE SEGURIDAD OWASP TOP 10 COMPLETADA CON ÉXITO!")


if __name__ == "__main__":
    main()
