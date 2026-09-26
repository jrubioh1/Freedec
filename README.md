# Freedec: Secure Document & Cryptographic Recovery Service

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.1-green.svg)](https://djangoproject.com)
[![DRF](https://img.shields.io/badge/DRF-3.15-red.svg)](https://www.django-rest-framework.org)
[![Security](https://img.shields.io/badge/Cryptography-DEK%20Envelopes%20%2B%20Fernet%20%2B%20SHA--256-orange.svg)](https://cryptography.io)
[![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-Compliant-brightgreen.svg)](https://owasp.org)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

<p align="center">
  <a href="#seccion-espanol"><b>🇪🇸 Leer en Español (Guía Completa para Principiantes)</b></a> &nbsp;&nbsp;|&nbsp;&nbsp; 
  <a href="#section-english"><b>🇬🇧 Read in English (Complete Beginner-Friendly Guide)</b></a>
</p>

---

<a id="seccion-espanol"></a>
# 🇪🇸 Español: Guía Completa de la Aplicación Freedec

Bienvenido a la documentación oficial de **Freedec**.

---

## 📑 Índice de Contenidos (Español)
1. [¿Qué es Freedec y qué problema resuelve?](#1-qué-es-freedec-y-qué-problema-resuelve)
2. [Requisitos Previos del Sistema](#2-requisitos-previos-del-sistema)
3. [Entorno de Pruebas Rápido (Staging Sandbox sin tocar tu proyecto)](#3-entorno-de-pruebas-rápido-staging-sandbox)
4. [Las 4 Opciones de Instalación en un Proyecto Existente](#4-las-4-opciones-de-instalación-en-un-proyecto-existente)
5. [Guía Paso a Paso de Integración (Línea por Línea)](#5-guía-paso-a-paso-de-integración-línea-por-línea)
6. [Cómo Funciona y Cómo se Usa la Web GUI (Navegador)](#6-cómo-funciona-y-cómo-se-usa-la-web-gui)
7. [Endpoints de la API REST (para Desarrolladores y cURL)](#7-endpoints-de-la-api-rest)
8. [Configuración de MEDIA en Producción (Nginx y Apache)](#8-configuración-de-media-en-producción-nginx-y-apache)
9. [Resolución de Problemas Frecuentes (FAQ / Troubleshooting)](#9-resolución-de-problemas-frecuentes-faq)

---

## 1. ¿Qué es Freedec y qué problema resuelve?

Compartir documentos de alta confidencialidad (contratos, auditorías, informes forenses) mediante contraseñas estáticas compartidas o canales tradicionales expone la información a filtraciones, ataques de fuerza bruta y permanencia innecesaria de archivos en los servidores.

**Freedec resuelve esto mediante una arquitectura criptográfica DEK multi-usuario, autorización dinámica por Enlace Mágico / OTP temporal y destrucción física irreversible al primer consumo (Burn-After-Read):**

1. **Arquitectura Criptográfica DEK Multi-Usuario con Sobres Digitales (`user_envelopes`)**:
   * Al registrar un documento, el sistema genera una **Clave Maestra de Datos simétrica única (DEK)** usando `Fernet.generate_key()`.
   * El archivo original se cifra **una sola vez** con esta DEK y se almacena en disco con extensión `.enc`.
   * Para cada correo autorizado en `allowed_emails`, se genera un secreto individual (`user_secret`), se cifra la DEK con este secreto y se protege el secreto con la clave de servidor (`settings.FREEDEC_FERNET_KEY`).
   * No existen contraseñas estáticas globales compartidas.
2. **Autorización Dinámica y Prueba de Posesión en Tiempo Real**:
   * El destinatario solicita el acceso subiendo su copia del archivo `.enc` e indicando su correo electrónico.
   * El sistema genera un token de un solo uso de alta entropía (`secrets.token_urlsafe(32)`) y un código OTP numérico de 6 dígitos con **expiración estricta a 15 minutos**.
   * En la base de datos **solo se almacena el hash SHA-256 del token** (Zero-Knowledge).
   * El enlace directo (`https://dominio/freedec/consumir/?t={token}`) y el código OTP se envían de forma exclusiva a la bandeja de entrada del usuario verificado.
3. **Descifrado al Vuelo y Destrucción Física (Burn-After-Read)**:
   * Al hacer clic en el Enlace Mágico o ingresar el OTP, el sistema abre el sobre digital del usuario, recupera la DEK y entrega el archivo original descifrado.
   * **Destrucción Física Inmediata**: El archivo cifrado `.enc` en disco se **elimina de forma física e irreversible** (`document.encrypted_file.delete(save=False)`).
   * El registro en base de datos se marca `is_consumed = True`, guardando `consumed_by` y `consumed_at`.
4. **Gestión de Accesos Posteriores**:
   * Si otro usuario autorizado intenta solicitar o descifrar un documento ya consumido, el sistema no produce errores 500 ni fuga datos. En su lugar, le envía automáticamente un correo con asunto `[Freedec] Archivo ya retirado: {nombre_documento}` informando: *"El documento '{nombre_documento}' ya fue retirado por {consumed_by} el {consumed_at}. Solicite una copia directamente a esa dirección."*
5. **Acceso Administrativo Preservado (Audit Bypass)**:
   * El personal administrativo autorizado en Django Admin puede descargar una copia original descifrada para fines de auditoría o contingencia usando la clave de servidor **sin destruir el archivo en disco ni marcarlo como consumido**, registrando el evento como `admin_inspeccion_preservada`.

---

## 2. Requisitos Previos del Sistema

* **Python 3.11 o 3.12** (`python3 --version`).
* **Poetry (Gestor moderno de dependencias en Python)**:
  ```bash
  curl -sSL https://install.python-poetry.org | python3 -
  ```

---

## 3. Entorno de Pruebas Rápido (Staging Sandbox)

El repositorio incluye un entorno de prueba autónomo preconfigurado listo para funcionar.

### Paso 1: Clonar e Instalar Dependencias
```bash
git clone https://github.com/jrubioh1/Freedec.git
cd Freedec
poetry install
```

### Paso 2: Inicializar la Base de Datos de Prueba
```bash
poetry run python manage.py setup_staging
```
*Crea la base de datos local SQLite, el usuario administrador `admin` con contraseña `admin123` y el archivo de prueba `sample_document.pdf`.*

### Paso 3: Arrancar el Servidor
```bash
poetry run python manage.py runserver 8000
```

### Paso 4: Probar la Interfaz Gráfica en tu Navegador
* **Portal de Solicitud de Acceso**: [http://127.0.0.1:8000/freedec/](http://127.0.0.1:8000/freedec/)
* **Portal de Consumo y Descarga (Burn-After-Read)**: [http://127.0.0.1:8000/freedec/consumir/](http://127.0.0.1:8000/freedec/consumir/)
* **Panel de Administrador (Django Admin)**: Inicia sesión en [http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/) (usuario `admin`, contraseña `admin123`) para registrar y cifrar documentos desde **Documentos Cifrados -> Añadir**.

### Paso 5: Probar el Flujo Automatizado por CLI (Opcional)
En otra terminal distinta, ejecuta:
```bash
poetry run python scripts/demo_flow.py
```

---

## 4. Las 4 Opciones de Instalación en un Proyecto Existente

Si ya tienes un proyecto Django funcionando, puedes incorporar `freedec` de cualquiera de estas 4 maneras:

### Opción 1: Copiar la carpeta `freedec/` a tu proyecto (La más directa)
* **¿Qué se copia?**: **ÚNICAMENTE la carpeta `freedec/`**.
* **¿Qué NO se copia?**: **NO copies `config/` ni `manage.py`** (tu proyecto ya tiene los suyos propios).
* **Dependencias**:
  ```bash
  poetry add cryptography djangorestframework
  ```

### Opción 2: Como dependencia Git con Poetry
```bash
poetry add git+https://github.com/jrubioh1/Freedec.git
```

### Opción 3: Como submódulo Git
```bash
git submodule add https://github.com/jrubioh1/Freedec.git apps/freedec
```

### Opción 4: Como paquete editable local
```bash
poetry add --editable /ruta/a/Freedec/
```

---

## 5. Guía Paso a Paso de Integración (Línea por Línea)

### Paso 1: Generar la Clave Maestra del Servidor (`FREEDEC_FERNET_KEY`)
Ejecuta en tu terminal:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Paso 2: Configurar tu `settings.py`
Añade las siguientes configuraciones en tu proyecto:

```python
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# 1. Añadir 'rest_framework' y 'freedec.apps.FreedecConfig' a INSTALLED_APPS
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Freedec y dependencias:
    'rest_framework',
    'freedec.apps.FreedecConfig',
]

# 2. Clave maestra Fernet del servidor (Reversible solo para el backend y staff autorizado)
FREEDEC_FERNET_KEY = os.environ.get(
    "FREEDEC_FERNET_KEY",
    "Pega_Aqui_La_Clave_Generada_En_El_Paso_1=="
)

# 3. Tamaño máximo de archivo (50 MB por defecto)
FREEDEC_MAX_FILE_SIZE = 50 * 1024 * 1024

# 4. Configurar almacenamiento MEDIA
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# 5. Configurar correo electrónico (SMTP en producción)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
DEFAULT_FROM_EMAIL = 'no-reply@tudominio.com'

# 6. Throttling de seguridad en DRF
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': ['rest_framework.throttling.AnonRateThrottle'],
    'DEFAULT_THROTTLE_RATES': {'anon': '10/minute'},
}
```

### Paso 3: Editar tu archivo `urls.py` principal
```python
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('freedec/', include('freedec.urls', namespace='freedec')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

### Paso 4: Ejecutar Migraciones
```bash
poetry run python manage.py migrate
```

---

## 6. Cómo Funciona y Cómo se Usa la Web GUI

### A. Panel de Administración (Django Admin - `http://localhost:8000/admin/`)
1. Inicia sesión en `/admin/` con una cuenta de staff/superusuario.
2. Entra a **Documentos Cifrados -> Añadir Documento Cifrado**.
3. Selecciona tu documento en formato admitido (**PDF, LibreOffice .odt/.ods o Microsoft Office .docx/.xlsx**).
4. Introduce las direcciones de correo autorizadas con el control dinámico `➕ Añadir otro correo`.
5. Pulsa **Guardar**.
6. **Resultado**:
   * El sistema genera la DEK, cifra el binario una sola vez y construye los sobres digitales individuales (`user_envelopes`).
   * La vista muestra la insignia de estado (`🟢 Activo (Listo para consumo)`).
   * Se habilita el botón `📥 .enc` para descargar el archivo cifrado y distribuirlo libremente.
   * Se habilita el botón **`🔓 Original (Admin)`** para realizar una descarga administrativa descifrada sin destruir el archivo en disco ni marcarlo como consumido (**Audit Bypass**).

---

### B. Portal Público de Solicitud de Acceso (`http://localhost:8000/freedec/`)
1. El usuario final o destinatario accede a `http://localhost:8000/freedec/` (o `/freedec/solicitar/`).
2. Sube su copia del archivo `.enc` (o el documento de control).
3. Introduce su correo electrónico registrado.
4. Pulsa **Solicitar Enlace de Acceso y OTP**.
5. **Resultado**:
   * La web muestra una respuesta genérica neutra (mitigación anti-enumeración de usuarios y archivos).
   * Si el archivo y correo coinciden con un documento activo:
     - Se genera un token de un solo uso y un código OTP de 6 dígitos con **expiración estricta de 15 minutos**.
     - Se despacha de forma automática un correo electrónico con el Magic Link (`https://dominio/freedec/consumir/?t={token}`) y el código OTP.
     - Se audita el evento con `action="solicitud_acceso"`.
   * Si el documento **ya había sido consumido**:
     - No se fugan datos. Se envía un correo informándole que el archivo ya fue retirado por `consumed_by` en `consumed_at`.
     - Se audita con `action="intento_post_consumo"`.

---

### C. Portal de Consumo y Descarga Destructiva (Burn-After-Read) (`http://localhost:8000/freedec/consumir/`)
1. El usuario hace clic en el **Enlace Mágico** recibido en su correo (`?t=...`) o accede a `/freedec/consumir/` e introduce su **código OTP de 6 dígitos** y correo electrónico.
2. **Resultado Inmediato**:
   * El sistema valida la vigencia del token/código (no expirado y no usado).
   * Abre el sobre digital del usuario para extraer la DEK y descifra el binario original en memoria.
   * Se inicia la descarga inmediata del archivo original en el navegador (`documento.pdf`, `contrato.docx`, etc.).
   * **Destrucción Física en Servidor**: El archivo `.enc` en disco es eliminado definitivamente mediante `encrypted_file.delete(save=False)`.
   * El estado en base de datos se actualiza: `is_consumed = True`, `consumed_by = email`, `consumed_at = timezone.now()`.
   * El token se marca como `is_used = True`.
   * Se audita con `action="descifrado_completado_burn"`.

---

### D. Descifrado por Terminal (Línea de Comandos CLI)
Para administradores, scripts o recuperación fuera de banda:
```bash
# Consumo y destrucción vía Magic Link token:
poetry run python manage.py decrypt_document ruta/archivo.enc --token "TOKEN_URLSAFE"

# Consumo y destrucción vía código OTP:
poetry run python manage.py decrypt_document ruta/archivo.enc --otp "123456" --email "usuario@empresa.com"

# Descarga administrativa preservada (Audit Bypass, sin destruir el archivo):
poetry run python manage.py decrypt_document ruta/archivo.enc --admin
```

---

### E. Eliminación Administrativa de Documentos
```bash
# Listar documentos existentes y su estado de consumo (🟢 Activo / 🔥 Consumido):
poetry run python manage.py delete_document --list

# Eliminar un documento específico:
poetry run python manage.py delete_document balance_anual.pdf

# Eliminar todos los registros y archivos físicos (.enc):
poetry run python manage.py delete_document --all
```

---

## 7. Endpoints de la API REST

### 1. Solicitud Pública de Acceso (`POST /freedec/public/request-access/`)
* **Headers**: Sin autenticación (`AnonRateThrottle`).
* **Form-Data**:
  * `file`: Archivo cifrado `.enc` o documento de control.
  * `email`: Dirección de correo electrónico del destinatario.

```bash
curl -X POST http://127.0.0.1:8000/freedec/public/request-access/ \
  -F "file=@contrato.pdf.enc" \
  -F "email=auditor@empresa.com"
```

* **Respuesta Exitosa / Neutra (`HTTP 200 OK`)**:
```json
{
  "status": "processed",
  "message": "Si el archivo y el correo electrónico coinciden con un documento activo y autorizado, se ha enviado un enlace de acceso y un código OTP a su bandeja de entrada."
}
```

---

### 2. Consumo y Descarga Directa por Magic Link (`GET /freedec/api/public/consume/?t=...`)
* **Query Param**: `t` (token URL-safe recibido en el correo).
* **Respuesta**: Binario original en `HTTP 200 OK` con cabecera `Content-Disposition: attachment; filename="documento.pdf"`.
* **Efecto colateral**: Destrucción física del binario en disco en el servidor (Burn-After-Read).

```bash
curl -OJ "http://127.0.0.1:8000/freedec/api/public/consume/?t=TOKEN_URLSAFE"
```

---

### 3. Consumo y Descarga por Código OTP (`POST /freedec/api/public/consume/`)
* **Headers**: `Content-Type: application/json`
* **JSON Body**:
```json
{
  "otp_code": "123456",
  "email": "auditor@empresa.com"
}
```

```bash
curl -X POST http://127.0.0.1:8000/freedec/api/public/consume/ \
  -H "Content-Type: application/json" \
  -d '{"otp_code": "123456", "email": "auditor@empresa.com"}' \
  --output documento_descifrado.pdf
```

---

## 8. Configuración de MEDIA en Producción (Nginx y Apache)

> [!IMPORTANT]
> **¿Por qué NUNCA se usa `static()` en producción?**  
> Cuando pones `DEBUG = False`, Django desactiva el servicio de archivos estáticos y media para proteger la memoria y el rendimiento del servidor. En producción, **Nginx o Apache deben entregar la carpeta `/media/` directamente desde el disco**.

### Opción A: Configuración en **Nginx**
```nginx
server {
    listen 443 ssl http2;
    server_name tudominio.com;

    location /media/ {
        alias /var/www/tu_proyecto/media/;
        autoindex off;
        add_header X-Content-Type-Options "nosniff";
        default_type application/octet-stream;
        location ~* \.(php|py|sh|pl|cgi|exe)$ { deny all; }
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Opción B: Configuración en **Apache (httpd con mod_wsgi)**
```apache
<VirtualHost *:443>
    ServerName tudominio.com

    Alias /media/ /var/www/tu_proyecto/media/

    <Directory /var/www/tu_proyecto/media>
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
        <IfModule mod_headers.c>
            Header always set X-Content-Type-Options "nosniff"
        </IfModule>
        <FilesMatch "\.(php|py|sh|pl|cgi|exe)$">
            Require all denied
        </FilesMatch>
        ForceType application/octet-stream
    </Directory>

    WSGIScriptAlias / /var/www/tu_proyecto/config/wsgi.py
</VirtualHost>
```

---

## 9. Resolución de Problemas Frecuentes (FAQ)

### ¿Qué ocurre si un enlace expira?
Los enlaces y códigos OTP tienen una vigencia estricta de 15 minutos. Si el usuario no realiza la descarga en ese intervalo, el token queda invalidado y deberá solicitar uno nuevo introduciendo nuevamente su archivo y correo en el portal.

### ¿Se puede recuperar un archivo una vez consumido?
No. La política **Burn-After-Read** elimina físicamente los bytes del archivo cifrado de disco (`save=False`). Por motivos de seguridad y privacidad, el usuario que intente descargarlo posteriormente recibirá una notificación indicándole quién retiró el documento para que le solicite una copia directamente.

---
---

<a id="section-english"></a>
# 🇬🇧 English: Complete Freedec Guide

Welcome to the official **Freedec** documentation.

---

## 📑 Table of Contents (English)
1. [What is Freedec and what problem does it solve?](#1-what-is-freedec-and-what-problem-does-it-solve)
2. [System Prerequisites](#2-system-prerequisites)
3. [Quick Staging Sandbox](#3-quick-staging-sandbox)
4. [Installation Options](#4-installation-options)
5. [Step-by-Step Integration Guide](#5-step-by-step-integration-guide)
6. [Web GUI Usage & Lifecycle](#6-web-gui-usage--lifecycle)
7. [REST API Endpoints](#7-rest-api-endpoints)
8. [Production MEDIA Configuration (Nginx & Apache)](#8-production-media-configuration-nginx--apache)
9. [FAQ & Security Operations](#9-faq--security-operations)

---

## 1. What is Freedec and what problem does it solve?

Sharing sensitive files using static passwords or conventional channels creates vulnerability windows: credentials can be leaked, files remain indefinitely on servers, and authorized recipients risk unauthorized third-party access.

**Freedec resolves this using a Multi-User DEK Envelope architecture, dynamic Proof-of-Possession via 15-minute Magic Link / OTP, and irreversible physical deletion upon first download (Burn-After-Read):**

1. **Multi-User Data Encryption Key (DEK) Architecture**:
   * Each document is encrypted once using a symmetric Data Encryption Key (`Fernet.generate_key()`).
   * Individual digital envelopes (`user_envelopes`) are constructed for every email in `allowed_emails`: the DEK is encrypted with a unique random user secret, and that secret is wrapped with the server master key (`settings.FREEDEC_FERNET_KEY`).
   * Eliminates static shared passwords.
2. **Dynamic Real-Time Proof-of-Possession**:
   * Recipients request access by submitting the `.enc` file and their email.
   * Generates a 32-byte URL-safe token and a 6-digit OTP code with strict **15-minute expiration**.
   * Only the **SHA-256 hash** of the token is persisted in the database (Zero-Knowledge).
   * Direct Magic Links (`/freedec/consumir/?t={token}`) and OTP codes are delivered exclusively to the verified inbox.
3. **Burn-After-Read (Destructive Consumption)**:
   * As soon as an authorized recipient downloads the document, the physical `.enc` file is permanently deleted from storage (`document.encrypted_file.delete(save=False)`).
   * The database record is updated to `is_consumed = True`, storing `consumed_by` and `consumed_at`.
4. **Post-Consumption Management**:
   * Subsequent access requests automatically email the requester with subject `[Freedec] Archivo ya retirado: {document_name}` stating that the document '{document_name}' was already claimed by `{consumed_by}` on `{consumed_at}` and directing them to ask that person for a copy.
5. **Non-Destructive Administrative Access (Audit Bypass)**:
   * Authenticated staff in Django Admin can download the decrypted original document using the server key without destroying the file and without setting `is_consumed = True`, logging `admin_inspeccion_preservada`.

---

## 2. System Prerequisites

* **Python 3.11 or 3.12** (`python3 --version`).
* **Poetry Package Manager**:
  ```bash
  curl -sSL https://install.python-poetry.org | python3 -
  ```

---

## 3. Quick Staging Sandbox

```bash
git clone https://github.com/jrubioh1/Freedec.git
cd Freedec
poetry install
poetry run python manage.py setup_staging
poetry run python manage.py runserver 8000
```
* **Request Access**: [http://127.0.0.1:8000/freedec/](http://127.0.0.1:8000/freedec/)
* **Consume Document (Burn-After-Read)**: [http://127.0.0.1:8000/freedec/consumir/](http://127.0.0.1:8000/freedec/consumir/)
* **Django Admin**: [http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/) (`admin` / `admin123`)

---

## 4. Installation Options

* **Option 1**: Copy `freedec/` into your project and add `cryptography` + `djangorestframework`.
* **Option 2**: Add via Git with Poetry: `poetry add git+https://github.com/jrubioh1/Freedec.git`.
* **Option 3**: Add as Git submodule: `git submodule add https://github.com/jrubioh1/Freedec.git apps/freedec`.

---

## 5. Step-by-Step Integration Guide

1. **Generate Master Server Key**:
   ```bash
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
2. **Add to `settings.py`**:
   ```python
   INSTALLED_APPS += ['rest_framework', 'freedec.apps.FreedecConfig']
   FREEDEC_FERNET_KEY = os.environ.get("FREEDEC_FERNET_KEY", "YOUR_KEY==")
   FREEDEC_MAX_FILE_SIZE = 50 * 1024 * 1024
   MEDIA_URL = '/media/'
   MEDIA_ROOT = BASE_DIR / 'media'
   ```
3. **Mount URLs in `urls.py`**:
   ```python
   path('freedec/', include('freedec.urls', namespace='freedec')),
   ```
4. **Run migrations**:
   ```bash
   poetry run python manage.py migrate
   ```

---

## 6. Web GUI Usage & Lifecycle

1. **Django Admin Upload**: Staff uploads the document and specifies allowed emails. DEK and user envelopes are created automatically.
2. **Public Request**: The recipient uploads the `.enc` file and enters their email at `/freedec/`. Receives a 15-minute Magic Link and OTP.
3. **Burn-After-Read Download**: Clicking the Magic Link or submitting the OTP downloads the original document and immediately deletes the `.enc` file from disk.
4. **Preserved Admin Download**: Staff can click **`🔓 Original (Admin)`** in Django Admin to download a decrypted copy without destroying the file.

---

## 7. REST API Endpoints

### 1. Request Access (`POST /freedec/public/request-access/`)
```bash
curl -X POST http://127.0.0.1:8000/freedec/public/request-access/ \
  -F "file=@contract.pdf.enc" \
  -F "email=auditor@corp.com"
```

### 2. Direct Magic Link Consumption (`GET /freedec/api/public/consume/?t=...`)
```bash
curl -OJ "http://127.0.0.1:8000/freedec/api/public/consume/?t=TOKEN_URLSAFE"
```

### 3. OTP Code Consumption (`POST /freedec/api/public/consume/`)
```bash
curl -X POST http://127.0.0.1:8000/freedec/api/public/consume/ \
  -H "Content-Type: application/json" \
  -d '{"otp_code": "123456", "email": "auditor@corp.com"}' \
  --output original_document.pdf
```

---

## 8. Production MEDIA Configuration (Nginx & Apache)

In production (`DEBUG = False`), web servers like Nginx or Apache must serve `/media/` directly from disk storage with `autoindex off` and script execution blocked.

---

## 9. FAQ & Security Operations

* **What happens if a Magic Link expires?** All tokens strictly expire after 15 minutes. The user must request access again.
* **Can a consumed file be recovered?** No. Burn-after-read physically deletes the binary file from disk.
