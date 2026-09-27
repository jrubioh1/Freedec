# Freedec: Sistema de Entrega y Canje Desatendido de Documentos Confidenciales

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.2-green.svg)](https://djangoproject.com)
[![DRF](https://img.shields.io/badge/DRF-3.15-red.svg)](https://www.django-rest-framework.org)
[![Security](https://img.shields.io/badge/Cryptography-SHA--256%20%2B%20OTP%20%2B%20Fernet%20DEK-orange.svg)](https://cryptography.io)
[![Zeroization](https://img.shields.io/badge/Shredding-Zeroization%20(os.urandom)-darkgreen.svg)](https://owasp.org)
[![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-Compliant-brightgreen.svg)](https://owasp.org)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

<p align="center">
  <a href="#seccion-espanol"><b>🇪🇸 Leer en Español (Guía Completa)</b></a> &nbsp;&nbsp;|&nbsp;&nbsp; 
  <a href="#section-english"><b>🇬🇧 Read in English (Full Guide)</b></a>
</p>

---

<a id="seccion-espanol"></a>
# 🇪🇸 Español: Guía de Freedec

Bienvenido a la documentación de **Freedec**, una aplicación Django diseñada para la **entrega y canje desatendido de documentos confidenciales con datos personales**, basada en el cotejo unívoco del Hash SHA-256 del archivo y verificación en tiempo real por OTP (One-Time Password).

---

## 🛡️ Principios de Diseño y Reglas de Oro

1. **CERO TRANSPORTE DEL BINARIO POR EL CLIENTE**:
   El usuario final **NUNCA** sube el archivo `.enc` para identificarse o solicitar acceso. El localizador oficial y prueba de trámite es exclusivamente el **hash SHA-256** del archivo original (cadena hexadecimal de 64 caracteres).
2. **SIN CONTRASEÑAS HUMANAS (Zero Human-Readable Passwords)**:
   Ningún usuario ni administrador visualiza, ingresa o gestiona contraseñas en texto claro. El descifrado es 100% interno y desatendido por el propio código del backend en memoria RAM tras validar el OTP.
3. **BURN-AFTER-READ CON DESTRUCCIÓN SEGURA (Zeroization/Shredding)**:
   Al primer canje exitoso por un usuario autorizado, el archivo cifrado en disco se sobrescribe con bytes criptográficamente aleatorios (`os.urandom(file_size)`), forzando la sincronización en disco físico con `flush()` y `os.fsync()` antes de desvincularlo del sistema de archivos (`os.remove()`), y el registro pasa a estado consumido.

---

## 📑 Índice de Contenidos
1. [Flujo Criptográfico y Operativo](#1-flujo-criptográfico-y-operativo)
2. [Entorno de Pruebas y Sandbox de Staging](#2-entorno-de-pruebas-y-sandbox-de-staging)
3. [Uso de la Interfaz Web (Web GUI)](#3-uso-de-la-interfaz-web-web-gui)
4. [Gestión en Django Admin](#4-gestión-en-django-admin)
5. [Endpoints de la API REST](#5-endpoints-de-la-api-rest)
6. [Comandos de Gestión CLI](#6-comandos-de-gestión-cli)
7. [Configuración de Seguridad en settings.py](#7-configuración-de-seguridad-en-settingspy)

---

## 1. Flujo Criptográfico y Operativo

### Alta del Documento (Admin):
1. El administrador sube el documento original (PDF, LibreOffice u Office) y especifica la lista de correos autorizados.
2. El sistema valida las cabeceras binarias (**Magic Bytes**) y calcula el **hash SHA-256** mediante lectura en bloques de 64 KB (anti-DoS/OOM).
3. Genera una **Clave Maestra de Datos (DEK)** única con `Fernet.generate_key()`.
4. Cifra el contenido del archivo con la DEK y lo guarda en disco como `.enc`.
5. Cifra la DEK internamente con la clave maestra del servidor `settings.FREEDEC_FERNET_KEY` y la almacena en `encrypted_dek`.
6. El administrador entrega el **Hash SHA-256** al usuario como prueba y localizador oficial.

### Solicitud de Acceso:
1. El usuario final accede a `/freedec/solicitar/` e introduce el Hash SHA-256 y su correo electrónico (o mediante enlace con `?hash=...`).
2. Si el hash no existe o el correo no está autorizado, el backend ejecuta un cálculo simulado PBKDF2 para neutralizar ataques de temporización (**Timing Attacks**) y devuelve una respuesta neutra preventiva.
3. Si el documento ya fue consumido (`is_consumed == True`), envía un correo formal al solicitante notificando quién y cuándo lo retiró (`consumed_by`, `consumed_at`), registrando `intento_post_consumo` en la auditoría.
4. Si está activo y autorizado, genera un código **OTP numérico de 6 dígitos** (`secrets.choice`), fija caducidad estricta a 15 minutos, envía el código por correo con enlace a `/freedec/canjear/` y audita `otp_enviado`.

### Canje y Destrucción Física (Burn-After-Read):
1. El usuario introduce el código OTP en `/freedec/canjear/`.
2. Se valida el código mediante comparación en tiempo constante (`secrets.compare_digest`). Si falla 3 veces, el token se bloquea definitivamente (`otp_invalido_bloqueado`).
3. Al validar el OTP, el backend descifra la DEK en RAM usando `FREEDEC_FERNET_KEY`, descifra los bytes del archivo original en memoria, ejecuta la **sobrescritura física con bytes aleatorios (`os.urandom`)** y borrado en disco, marca el documento como consumido y devuelve inmediatamente un `FileResponse` con el archivo original en memoria.

---

## 2. Entorno de Pruebas y Sandbox de Staging

### Instalación con Poetry
```bash
# Clonar e instalar dependencias
git clone https://github.com/jrubioh1/Freedec.git
cd Freedec
poetry install

# Aplicar migraciones
poetry run python manage.py migrate

# Inicializar entorno staging (crea superusuario 'admin' / 'admin123' y sample_document.pdf)
poetry run python manage.py setup_staging
```

### Ejecutar Suite de Pruebas Automatizadas
```bash
poetry run pytest -v
```

### Ejecutar Demostración Completa del Flujo
```bash
poetry run python scripts/demo_flow.py
```

---

## 3. Uso de la Interfaz Web (Web GUI)

* **Solicitar Acceso (`/freedec/solicitar/`)**:
  * Formulario limpio con dos campos: **Hash SHA-256** y **Correo Electrónico**.
  * Soporta parámetro URL directo: `/freedec/solicitar/?hash=<SHA256>`.
  * Redirige a la vista de canje guardando los datos en sesión.
* **Canjear OTP (`/freedec/canjear/`)**:
  * Entrada del código OTP numérico de 6 dígitos.
  * Entrega inmediata del archivo original vía descarga de navegador (`FileResponse`).
  * Destrucción simultánea del archivo cifrado en disco.

---

## 4. Gestión en Django Admin

* **Panel `EncryptedDocumentAdmin`**:
  * Columnas: `original_filename`, `file_hash`, `burn_policy`, `consumption_status_badge`, `audit_download_button`, `corporate_email_button`, `delete_action_button`.
  * **Cero contraseñas**: Ningún campo muestra ni almacena contraseñas humanas.
  * **Descripción editable del documento**: Campo editable con valor corporativo por defecto, modificable tanto en el alta como en la edición y durante procesos de reactivación. Esta descripción se incorpora automáticamente en todas las notificaciones por correo electrónico (OTP, avisos de retirada y advertencias).
  * **Plantilla de Correo Corporativo (📋 / 📨)**:
    * Botón `📋 Copiar texto correo` en el listado para copiar instantáneamente al portapapeles el texto oficial corporativo con el nombre del archivo, su descripción, el Hash SHA-256 y el enlace directo de acceso.
    * Panel en el detalle del documento con visor del texto preformateado, botón de copia y enlace directo para abrir el cliente de correo (`mailto:`).
  * **Selector de Política de Destrucción (`burn_policy`)**:
    * `⚡ 1er Acceso` (*FIRST_ACCESS*): Trituración y borrado físico inmediato tras el primer canje exitoso.
    * `👥 Todos` (*ALL_RECIPIENTS*): Cada destinatario autorizado dispone de una descarga individual; el archivo se preserva en disco hasta que todos los destinatarios hayan canjeado su copia.
  * **Verificación Dinámica y Reactivación**: Cálculo de SHA-256 en cliente con WebCrypto API; detecta si el documento ya existe y si hay destinatarios previos con canje pendiente, ofreciendo el botón `➕ Volver a añadir pendientes a la lista de correos` para reactivarlo sin colisiones y permitiendo actualizar la descripción.
  * **Eliminación y Trituración Directa (🗑️)**: Botón de borrado directo con permisos en cascada sobre tokens y registros de auditoría, ejecutando la destrucción física en disco (`shred_and_delete_file`).
  * **Descarga de Auditoría Administrativa**: Botón y acción que permite al personal staff con permiso `can_audit_download` descargar una copia descifrada para fines legales o de auditoría mientras el documento **no haya sido consumido**, **sin destruir el archivo ni marcarlo como consumido**, registrando `admin_descarga_preservada`.
  * Inline de auditoría legal de solo lectura (`DocumentAccessLogInline`).

---

## 5. Endpoints de la API REST

### 1. Solicitud de Código OTP
```bash
curl -X POST http://127.0.0.1:8000/freedec/api/public/request-access/ \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "4c7ded034bb71b3802a0f17dd37226ff26217f37388d1bc50d3a6bf774091497",
    "email": "destinatario@seguro.gob.es"
  }'
```
**Respuesta:**
```json
{
  "status": "processed",
  "message": "Si los datos indicados corresponden a un documento activo y una dirección de correo autorizada, recibirá en breves momentos un código de verificación (OTP) en su buzón."
}
```

### 2. Canje y Descarga con OTP
```bash
curl -X POST http://127.0.0.1:8000/freedec/api/public/consume/ \
  -H "Content-Type: application/json" \
  -d '{
    "file_hash": "4c7ded034bb71b3802a0f17dd37226ff26217f37388d1bc50d3a6bf774091497",
    "email": "destinatario@seguro.gob.es",
    "otp_code": "455653"
  }' \
  --output documento_descifrado.pdf
```

---

## 6. Comandos de Gestión CLI

```bash
# Listar todos los documentos registrados
poetry run python manage.py delete_document --list

# Descifrado por OTP mediante CLI (consumo y destrucción Burn-After-Read)
poetry run python manage.py decrypt_document <hash_o_archivo> --otp 123456 --email usuario@empresa.com

# Descarga de auditoría administrativa preservada (Audit Bypass)
poetry run python manage.py decrypt_document <hash_o_archivo> --admin --output copia_auditoria.pdf
```

---

## 7. Configuración de Seguridad en settings.py

```python
# Clave maestra Fernet obligatoria (32 bytes base64 url-safe)
# Generada con cryptography.fernet.Fernet.generate_key().decode()
FREEDEC_FERNET_KEY = "TU_CLAVE_FERNET_BASE64_URL_SAFE_DE_32_BYTES="

# Límite máximo de archivo permitido (50 MB)
FREEDEC_MAX_FILE_SIZE = 50 * 1024 * 1024
```

> **Validación en arranque:** `FreedecConfig.ready()` detiene el inicio de Django con `ImproperlyConfigured` si `FREEDEC_FERNET_KEY` no es válida o está ausente.

---
---

<a id="section-english"></a>
# 🇬🇧 English: Freedec Guide

Welcome to **Freedec**, a security-focused Django application for **unattended delivery and redemption of confidential documents with personal data**, based on strict SHA-256 file hash matching and real-time One-Time Password (OTP) verification.

---

## 🛡️ Design Principles & Golden Rules

1. **ZERO CLIENT BINARY TRANSPORT**: The client NEVER uploads the `.enc` file to identify themselves. The official locator is exclusively the SHA-256 hash (64 hex characters).
2. **ZERO HUMAN-READABLE PASSWORDS**: No plaintext passwords managed by users or admins. Decryption is 100% internal and unattended in RAM after validating the OTP.
3. **BURN-AFTER-READ WITH SECURE DESTRUCTION (Zeroization/Shredding)**: Upon the first successful redemption by an authorized user, the encrypted file on disk is overwritten with cryptographically random bytes (`os.urandom`), flushed and synced to physical storage (`flush()` / `os.fsync()`), and deleted from the filesystem (`os.remove()`).

---

## 📑 Table of Contents
1. [Cryptographic Lifecycle](#1-cryptographic-lifecycle)
2. [Testing & Sandbox Setup](#2-testing--sandbox-setup)
3. [Web GUI Usage](#3-web-gui-usage)
4. [Django Admin Management](#4-django-admin-management)
5. [REST API Endpoints](#5-rest-api-endpoints)
6. [CLI Management Commands](#6-cli-management-commands)
7. [Security Configuration in settings.py](#7-security-configuration-in-settingspy)

---

## 1. Cryptographic Lifecycle

* **Upload (Admin)**: File validated by Magic Bytes, unique DEK generated with `Fernet.generate_key()`, encrypted in storage as `.enc`, DEK encrypted with `FREEDEC_FERNET_KEY`. SHA-256 provided to recipient as sole locator.
* **Access Request**: User submits SHA-256 and email at `/freedec/solicitar/`. If unauthorized or non-existent, simulated PBKDF2 runs to prevent timing attacks. If consumed, email notice is dispatched and `intento_post_consumo` logged. If active and authorized, 6-digit cryptographic OTP is sent with 15-minute strict expiration.
* **Redemption (Burn-After-Read)**: User enters 6-digit OTP at `/freedec/canjear/`. Validated via `secrets.compare_digest` (locked after 3 failed attempts). File decrypted in memory, physical file on disk shredded with `os.urandom`, and delivered as `FileResponse` attachment.

---

## 2. Testing & Sandbox Setup

```bash
git clone https://github.com/jrubioh1/Freedec.git
cd Freedec
poetry install
poetry run python manage.py migrate
poetry run python manage.py setup_staging
poetry run pytest -v
poetry run python scripts/demo_flow.py
```

---

## 3. Web GUI Usage

* **Request Access (`/freedec/solicitar/`)**: SHA-256 hash and email input. Supports `?hash=...` prefilling.
* **Redeem OTP (`/freedec/canjear/`)**: 6-digit OTP input with immediate browser RAM streaming download and disk shredding.

---

## 4. Django Admin Management

* Model `EncryptedDocumentAdmin` with no password fields.
* Granular permission `can_audit_download` for preserved administrative audit inspection.
* Read-only legal access logs inline (`DocumentAccessLogInline`).

---

## 5. REST API Endpoints

* `POST /freedec/api/public/request-access/` (`file_hash`, `email`)
* `POST /freedec/api/public/consume/` (`file_hash`, `email`, `otp_code`)

---

## 6. CLI Management Commands

* `poetry run python manage.py delete_document --list`
* `poetry run python manage.py decrypt_document <hash> --otp 123456 --email user@corp.com`
* `poetry run python manage.py decrypt_document <hash> --admin --output audit.pdf`
