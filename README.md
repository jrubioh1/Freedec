# Freedec: Secure Document & Password Recovery Service

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue.svg)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.1-green.svg)](https://djangoproject.com)
[![DRF](https://img.shields.io/badge/DRF-3.15-red.svg)](https://www.django-rest-framework.org)
[![Security](https://img.shields.io/badge/Cryptography-Fernet%20%2B%20SHA--256-orange.svg)](https://cryptography.io)
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

Imagina que necesitas compartir un documento altamente confidencial (un contrato, una auditoría, unas credenciales maestras) con una lista específica de personas. Si envías el archivo y la contraseña por el mismo canal (por ejemplo, en el mismo correo o chat), cualquier persona que intercepte la comunicación tendrá acceso total.

**Freedec resuelve esto mediante una arquitectura descentralizada de conocimiento cero (Zero-Knowledge) y verificación multi-factor:**

1. **El Administrador sube el documento**:
   * El sistema calcula la **huella digital exacta del archivo (hash SHA-256)**. No se usan IDs secuenciales (como `documento/1`), lo que impide que atacantes adivinen URLs (anti-IDOR).
   * El archivo se cifra inmediatamente con **AES-128-CBC + HMAC-SHA256 (Fernet)** y se guarda protegido en disco.
   * Se genera un **Código Secreto de Acceso (`access_code`)** de 256 bits. El administrador recibe este código una sola vez para entregarlo en mano o por chat seguro (Signal/SMS). En la base de datos se guarda **hasheado** con PBKDF2 (incluso si roban la base de datos, nadie puede ver el código).
2. **El Destinatario recupera la clave**:
   * El usuario sube su copia del documento a la web de Freedec.
   * Introduce el `access_code` y su correo electrónico.
   * El sistema calcula el hash en tiempo real, verifica que posea el archivo original, comprueba el código y confirma que su correo esté en la lista blanca autorizada.
   * **La clave NUNCA se muestra en pantalla**: se envía de forma automatizada y exclusiva al buzón del correo verificado.

---

## 2. Requisitos Previos del Sistema

Antes de empezar, comprueba que tienes instaladas estas herramientas en tu ordenador o servidor:

* **Python 3.11 o 3.12**:
  Comprueba con:
  ```bash
  python3 --version
  ```
* **Poetry (Gestor moderno de dependencias en Python)**:
  Comprueba con:
  ```bash
  poetry --version
  ```
  *Si no tienes Poetry instalado, instálalo en Linux/macOS con:*
  ```bash
  curl -sSL https://install.python-poetry.org | python3 -
  ```

---

## 3. Entorno de Pruebas Rápido (Staging Sandbox)

El repositorio incluye un servidor de prueba autónomo preconfigurado. **No necesitas tener ningún proyecto Django previo para probarlo.**

### Paso 1: Clonar e Instalar Dependencias
```bash
git clone https://github.com/jrubioh1/Freedec.git
cd Freedec
poetry install
```

### Paso 2: Inicializar la Base de Datos de Prueba
Ejecuta el comando automatizado:
```bash
poetry run python manage.py setup_staging
```
*Creará una base de datos SQLite local (`db_staging.sqlite3`), creará el usuario administrador `admin` con contraseña `admin123` y generará un archivo de prueba legítimo `sample_document.pdf`.*

### Paso 3: Arrancar el Servidor
```bash
poetry run python manage.py runserver 8000
```

### Paso 4: Probar la Interfaz Gráfica en tu Navegador
* **Portal Público de Recuperación**: Abre [http://127.0.0.1:8000/freedec/](http://127.0.0.1:8000/freedec/) en tu navegador.
* **Portal Público de Descifrado (.enc)**: Abre [http://127.0.0.1:8000/freedec/descifrar/](http://127.0.0.1:8000/freedec/descifrar/) en tu navegador.
* **Portal de Subida de Administrador**: Inicia sesión en [http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/) (usuario `admin`, contraseña `admin123`) y entra a [http://127.0.0.1:8000/freedec/admin-upload/](http://127.0.0.1:8000/freedec/admin-upload/).

> [!TIP]
> **Configuración en claro y Presetting de Pruebas**: El proyecto funciona directamente sin necesidad de archivo `.env`.
> - `config/settings.py`: Define el **setting genérico** en claro (sin dependencias de `.env` ni credenciales privadas).
> - `config/presettings.py`: Contiene el presetting para pruebas locales con base de datos de staging y servidor SMTP real (**Ethereal Email**), permitiendo inspeccionar los correos de despacho en tiempo real en [https://ethereal.email/messages](https://ethereal.email/messages) ejecutando `python manage.py runserver --settings=config.presettings`.

### Paso 5: Probar el Flujo Automatizado por CLI (Opcional)
En otra terminal distinta, ejecuta:
```bash
poetry run python scripts/demo_flow.py
```

---

## 4. Las 4 Opciones de Instalación en un Proyecto Existente

Si ya tienes un proyecto Django funcionando, puedes incorporar `freedec` de cualquiera de estas 4 maneras:

### Opción 1: Copiar la carpeta `freedec/` a tu proyecto (La más sencilla y directa)
* **¿Qué se copia?**: **ÚNICAMENTE la carpeta `freedec/`**.
* **¿Qué NO se copia?**: **NO copies `config/` ni `manage.py`** (tu proyecto ya tiene los suyos propios).
* **Comando para instalar dependencias**:
  En la carpeta de tu proyecto existente:
  ```bash
  poetry add cryptography djangorestframework
  ```

#### Comparativa visual de directorios:
```text
Tu Proyecto ANTES de copiar:             Tu Proyecto DESPUÉS de copiar:
----------------------------             ------------------------------
mi_proyecto/                             mi_proyecto/
├── manage.py                            ├── manage.py
├── mi_config/                           ├── mi_config/
│   ├── settings.py                      │   ├── settings.py  <-- Añadir 4 líneas
│   ├── urls.py                          │   ├── urls.py      <-- Añadir 1 línea
│   └── wsgi.py                          │   └── wsgi.py
                                         └── freedec/         <-- ¡Solo pegas esto!
                                             ├── models.py
                                             ├── views.py
                                             ├── templates/
                                             └── ...
```

---

### Opción 2: Como dependencia Git con Poetry (Ideal para repositorios en equipo)
Si Freedec está en un repositorio Git remoto (GitHub, GitLab):
```bash
poetry add git+https://github.com/jrubioh1/Freedec.git
```
*Poetry clonará y gestionará las actualizaciones de Freedec como cualquier paquete estándar.*

---

### Opción 3: Enlace local editable con Poetry (Monorepos o Desarrollo Activo)
Si tienes el repositorio de Freedec descargado en tu misma máquina:
```bash
poetry add --editable /ruta/absoluta/a/Freedec
```
*Cualquier cambio que hagas en el código de Freedec se reflejará al instante en tu proyecto principal.*

---

### Opción 4: Como paquete de PyPI o Registro Privado
Si compilas y publicas Freedec:
```bash
# En el repositorio Freedec:
poetry build
poetry publish

# En tu proyecto principal:
poetry add freedec
```

---

## 5. Guía Paso a Paso de Integración (Línea por Línea)

Sigue estos 6 pasos numerados en tu proyecto Django existente:

### Paso 1: Generar la Clave Criptográfica Maestra
Abre tu terminal y ejecuta:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Obtendrás una cadena de 44 caracteres base64 similar a:
`2bXoO5W3uK_mZ6k9wE2qR7vA1yT8pI0uL4mN6jH3gD1=`

---

### Paso 2: Editar tu archivo `settings.py`
Abre el archivo `settings.py` de tu proyecto y añade lo siguiente:

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
    # Aplicaciones requeridas:
    'rest_framework',
    'freedec.apps.FreedecConfig',
]

# 2. Configurar la clave maestra que generaste en el Paso 1
# (En producción se recomienda inyectarla desde os.environ)
FREEDEC_FERNET_KEY = os.environ.get(
    "FREEDEC_FERNET_KEY",
    "Pega_Aqui_La_Clave_Generada_En_El_Paso_1=="
)

# 3. Tamaño máximo de archivo permitido (50 MB por defecto)
FREEDEC_MAX_FILE_SIZE = 50 * 1024 * 1024

# 4. Configurar las rutas de archivos MEDIA (si no las tenías)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# 5. Configurar el correo (Usa tu SMTP habitual en producción)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
DEFAULT_FROM_EMAIL = 'no-reply@tudominio.com'

# 6. Throttling de seguridad en DRF (protege el endpoint público)
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': ['rest_framework.throttling.AnonRateThrottle'],
    'DEFAULT_THROTTLE_RATES': {'anon': '5/minute'},
}
```

---

### Paso 3: Editar tu archivo `urls.py` principal
Abre el archivo `urls.py` de la carpeta de configuración de tu proyecto y añade el `include`:

```python
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Acoplar las rutas de Freedec (GUI y API REST)
    path('freedec/', include('freedec.urls', namespace='freedec')),
]

# Servir archivos multimedia únicamente durante desarrollo local:
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

---

### Paso 4: Ejecutar las Migraciones
Ejecuta en tu terminal para crear las tablas en tu base de datos:
```bash
poetry run python manage.py makemigrations freedec
poetry run python manage.py migrate
```

---

### Paso 5: Crear un Superusuario Administrador (si no tienes uno)
```bash
poetry run python manage.py createsuperuser
```
*Introduce un nombre de usuario, correo y contraseña.*

---

### Paso 6: Iniciar tu Servidor
```bash
poetry run python manage.py runserver
```
¡Listo! Ya tienes tanto la interfaz web como la API REST plenamente operativas en tu proyecto.

---

## 6. Cómo Funciona y Cómo se Usa la Web GUI

Una vez acoplado, tendrás los portales web accesibles desde cualquier navegador:

### A. Portal de Administración (`http://localhost:8000/freedec/admin-upload/` o Django Admin)
1. Inicia sesión primero con tu cuenta de administrador en `/admin/` (o la ruta de admin de tu proyecto).
2. Puedes registrar documentos desde `/admin/` (menú **Documentos Cifrados -> Añadir**) o desde la interfaz `/freedec/admin-upload/`.
3. Selecciona tu documento en formato permitido (**PDF, LibreOffice .odt/.ods o Microsoft Office .docx/.xlsx**).
4. Opcionalmente escribe una contraseña personalizada o déjalo vacío para que el sistema genere una automáticamente con alta entropía criptográfica (24 caracteres).
5. Escribe las direcciones de correo autorizadas (puedes pulsar el botón `+` para añadir múltiples destinatarios de forma interactiva).
6. Pulsa **Cifrar y Registrar** (o **Guardar** en el Admin).
7. **Resultado**:
   * **Descarga Automática de Recibo de Credenciales**: El navegador descargará al instante un archivo de texto `<nombre_original>_credenciales.txt` con el hash SHA-256, código secreto de acceso, contraseña y enlaces directos, para que el administrador pueda guardarlo de forma local sin que quede expuesto en claro en el servidor.
   * La pantalla mostrará el **Código de Acceso (`access_code`)** con botón de copiado rápido y la **Contraseña Asignada**.
   * Un botón para descargar el archivo cifrado `<nombre_original>.enc`.

---

### B. Portal Público de Solicitud de Contraseña (`http://localhost:8000/freedec/`)
1. El usuario final o destinatario entra a `http://localhost:8000/freedec/`.
2. Sube su copia del documento (bien el archivo original o el archivo `.enc` que le facilitaron).
3. Pega el código de acceso facilitado por el emisor.
4. Escribe su correo electrónico registrado en la lista de autorización.
5. Pulsa **Solicitar Contraseña**.
6. **Resultado**: La web mostrará un mensaje de confirmación neutro (anti-enumeración de usuarios). Si los datos son legítimos y el correo está autorizado:
   * El sistema enviará de inmediato la contraseña al correo del destinatario, **especificando explícitamente el nombre del documento** al que corresponde la clave y un enlace directo a la pestaña de descifrado.
   * El sistema registra el acceso en la tabla de auditoría (`DocumentAccessLog`), actualizando el contador `access_count`, la fecha de último acceso y la IP del solicitante.

---

### C. Portal Público de Descifrado de Archivos `.enc` (`http://localhost:8000/freedec/descifrar/`)
*¿Cómo se pasa del archivo `.enc` al documento original descifrado?*
1. El usuario abre `http://localhost:8000/freedec/descifrar/` (o pulsa **🔓 Descifrar Archivo (.enc)** en la barra de navegación).
2. Sube el archivo `.enc`.
3. Pega la contraseña que acaba de recibir en su correo electrónico.
4. Pulsa **Descifrar y Descargar Archivo Original**.
5. **Resultado**: El sistema valida la contraseña en memoria, descifra el contenedor con AES-128/Fernet y descarga inmediatamente el archivo original con su nombre y extensión correcta (`documento.pdf`, `contrato.docx`, etc.).

---

### D. Eliminación de Documentos y Borrado Físico en Disco (Derecho al Olvido / GDPR)
Al eliminar un documento registrado:
* **Señal `post_delete` automática**: Al borrar un documento desde el panel de Django Admin o el ORM, se elimina automáticamente su archivo físico `.enc` asociado en disco para evitar archivos confidenciales huérfanos.
* **Botón directo en Django Admin**: La tabla de documentos en `/admin/freedec/encrypteddocument/` dispone de un botón directo `🗑️ Eliminar` por cada fila.
* **Comando CLI de borrado**:
  ```bash
  # Listar documentos existentes
  poetry run python manage.py delete_document --list

  # Eliminar un documento específico por nombre o hash
  poetry run python manage.py delete_document balance_anual.pdf

  # Eliminar todos los registros y archivos físicos (.enc)
  poetry run python manage.py delete_document --all
  ```

---

### E. Compatibilidad con Despliegues en Apache (Múltiples Apps en el Mismo Dominio)
Freedec está diseñado específicamente para convivir con otras aplicaciones en el mismo servidor Apache:
* **Espacio de nombres aislado**: Todas las rutas cuelgan de `/freedec/` (ej. `http://dominio.com/freedec/`), sin invadir la raíz `/` ni rutas genéricas.
* **Resolución dinámica con SCRIPT_NAME**: En las plantillas HTML se usa `{% url 'freedec:gui-public-request' %}` y `{% url 'freedec:gui-public-decrypt' %}`, adaptándose automáticamente a subcarpetas como `WSGIScriptAlias /freedec` o `ProxyPass`.
* **Admin Desacoplado**: Los recibos y enlaces al panel de administración se resuelven dinámicamente mediante `reverse('admin:index')`, respetando la URL exacta que tu proyecto tenga configurada para Django Admin.

---

### F. Descifrado por Terminal (Línea de Comandos CLI)
Para administradores, scripts o usuarios avanzados:
```bash
poetry run python manage.py decrypt_document ruta/al/archivo.enc --password "TuContraseña" --output documento_recuperado.pdf
```

---

## 7. Endpoints de la API REST

Si deseas integrar Freedec con un frontend en React, Vue, Angular o una app móvil, utiliza los endpoints REST:

### 1. Subida Administrativa (`POST /freedec/api/admin/upload/`)
* **Headers**: `Authorization: Bearer <TOKEN>` o sesión activa.
* **Form-Data**:
  * `original_file`: Archivo binario.
  * `plain_password`: Contraseña.
  * `allowed_emails`: `["auditor@empresa.com"]`.

```bash
curl -X POST http://127.0.0.1:8000/freedec/api/admin/upload/ \
  -u admin:admin123 \
  -F "original_file=@documento.pdf" \
  -F "plain_password=ClaveSecreta#2026!" \
  -F 'allowed_emails=["auditor@empresa.com"]'
```

### 2. Recuperación Pública (`POST /freedec/api/public/request-password/`)
* **Headers**: Sin autenticación previa requerida (Público).
* **Form-Data**:
  * `file`: Archivo binario en posesión del usuario.
  * `access_code`: Código secreto.
  * `email`: Correo del usuario.

```bash
curl -X POST http://127.0.0.1:8000/freedec/api/public/request-password/ \
  -F "file=@documento.pdf" \
  -F "access_code=CODIGO_DE_ACCESO" \
  -F "email=auditor@empresa.com"
```

---

## 8. Configuración de MEDIA en Producción (Nginx y Apache)

> [!IMPORTANT]
> **¿Por qué NUNCA se usa `static()` en producción?**  
> Cuando pones `DEBUG = False`, Django desactiva `static()` para proteger el servidor. Servir archivos pesados desde Python consumiría toda la memoria y bloquearía a los demás usuarios. En producción, **Nginx o Apache deben entregar la carpeta `/media/` directamente desde el disco**.

### Opción A: Configuración en **Nginx**
Añade este bloque en tu archivo `/etc/nginx/sites-available/tudominio`:

```nginx
server {
    listen 443 ssl http2;
    server_name tudominio.com;

    # Servir la carpeta MEDIA directamente desde el disco:
    location /media/ {
        alias /var/www/tu_proyecto/media/;
        autoindex off;                          # Desactiva listado de archivos
        add_header X-Content-Type-Options "nosniff";
        default_type application/octet-stream;  # Fuerza descarga segura
        location ~* \.(php|py|sh|pl|cgi|exe)$ { deny all; } # Bloquea scripts
    }

    # Resto de la aplicación Django (Gunicorn):
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
Añade estas líneas dentro de tu VirtualHost (`/etc/apache2/sites-available/default-ssl.conf`):

```apache
<VirtualHost *:443>
    ServerName tudominio.com

    # 1. Alias para servir la carpeta /media/ desde el disco
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

    # 2. Conexión con Django vía mod_wsgi
    WSGIDaemonProcess tu_proyecto python-home=/var/www/tu_proyecto/.venv python-path=/var/www/tu_proyecto
    WSGIProcessGroup tu_proyecto
    WSGIScriptAlias / /var/www/tu_proyecto/config/wsgi.py
</VirtualHost>
```

---

## 9. Resolución de Problemas Frecuentes (FAQ)

### ¿Error: `ImproperlyConfigured: Falta la configuración FREEDEC_FERNET_KEY`?
* **Causa**: No has definido la clave maestra en tu `settings.py`.
* **Solución**: Genera una con `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` y colócala en `settings.py`.

### ¿Error 404 al intentar descargar el archivo cifrado `.enc`?
* **Causa en desarrollo**: Falta la línea `urlpatterns += static(settings.MEDIA_URL, ...)` en tu `urls.py`.
* **Causa en producción**: No has configurado el alias `/media/` en tu servidor Nginx o Apache.

### ¿No llega el correo con la contraseña al destinatario?
* **Causa en desarrollo / sandbox por defecto**: Tienes `EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'`. La contraseña se imprime en la terminal donde corre Django, no se envía por internet.
* **Solución**: Configura tu servidor SMTP en un archivo `.env` en la raíz (copiando `.env.example`). Dispones de plantillas para Gmail, Brevo, Outlook, etc. Puedes comprobar tu conexión SMTP al instante ejecutando:
  ```bash
  poetry run python manage.py test_smtp tu-correo@gmail.com
  ```

### ¿Qué sucede cuando elimino un registro de documento cifrado?
* **Eliminación física garantizada**: Gracias al receptor de señales `post_delete`, cuando se elimina un registro (sea individualmente desde el Admin, por lotes o mediante `QuerySet.delete()`), el archivo físico `.enc` asociado en disco (`media_staging/encrypted_docs/`) se destruye automáticamente del sistema de archivos, garantizando el cumplimiento de borrado seguro y GDPR.

### ¿Error: `Tipo de archivo no permitido`?
* **Causa**: Solo se admiten archivos **PDF, LibreOffice (.odt, .ods, .odp, .odg) y MS Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt)**. No se permiten archivos de texto plano `.txt`, ejecutables `.exe` ni scripts `.sh`.

---
---

<a id="section-english"></a>
# 🇬🇧 English: Complete Guide for Freedec Application

Welcome to the official documentation for **Freedec**. 

---

## 📑 Table of Contents (English)
1. [What is Freedec and what problem does it solve?](#1-what-is-freedec-and-what-problem-does-it-solve)
2. [System Prerequisites](#2-system-prerequisites)
3. [Quick Test Sandbox (Staging mode without touching your project)](#3-quick-test-sandbox-staging-mode)
4. [The 4 Installation Options into an Existing Project](#4-the-4-installation-options-into-an-existing-project)
5. [Step-by-Step Integration Checklist (Line by Line)](#5-step-by-step-integration-checklist-line-by-line)
6. [How the Web GUI Works and How to Use It](#6-how-the-web-gui-works-and-how-to-use-it)
7. [REST API Endpoints (for Developers and cURL)](#7-rest-api-endpoints)
8. [Production MEDIA Configuration (Nginx & Apache)](#8-production-media-configuration-nginx--apache)
9. [Frequently Asked Questions (FAQ / Troubleshooting)](#9-frequently-asked-questions-faq--troubleshooting)

---

## 1. What is Freedec and what problem does it solve?

Imagine you need to share a highly confidential document (a contract, an audit, master database credentials) with a specific list of recipients. If you send both the file and the password over the same channel (e.g. in the same email or chat), any attacker who intercepts the communication gains full access.

**Freedec solves this through a decentralized Zero-Knowledge architecture and multi-factor verification:**

1. **The Administrator uploads the document**:
   * The system computes the **exact digital fingerprint of the file (SHA-256 hash)**. No sequential IDs (like `document/1`) are used, completely preventing Insecure Direct Object References (anti-IDOR).
   * The file is encrypted immediately using **AES-128-CBC + HMAC-SHA256 (Fernet)** and securely saved to disk.
   * A 256-bit **Secret Access Code (`access_code`)** is generated. The administrator receives this code once to hand over in person or via secure channel (Signal/SMS). In the database, it is stored **hashed with PBKDF2** (even if attackers dump the database, they cannot view the code).
2. **The Recipient retrieves the password**:
   * The user uploads their copy of the document to the Freedec web portal.
   * Enters the `access_code` and their email address.
   * The system calculates the SHA-256 hash in real time, verifies possession of the exact file, checks the access code, and confirms their email is whitelisted.
   * **The password is NEVER shown on the screen**: it is dispatched automatically and exclusively to the inbox of the verified email address.

---

## 2. System Prerequisites

Verify that your system has the following tools installed:

* **Python 3.11 or 3.12**:
  Check with:
  ```bash
  python3 --version
  ```
* **Poetry (Modern Python dependency manager)**:
  Check with:
  ```bash
  poetry --version
  ```
  *If not installed, install it on Linux/macOS using:*
  ```bash
  curl -sSL https://install.python-poetry.org | python3 -
  ```

---

## 3. Quick Test Sandbox (Staging Mode)

The repository provides a standalone preconfigured test server. **You do not need an existing Django project to evaluate it.**

### Step 1: Clone and Install Dependencies
```bash
git clone https://github.com/jrubioh1/Freedec.git
cd Freedec
poetry install
```

### Step 2: Initialize Test Database
Run the automated command:
```bash
poetry run python manage.py setup_staging
```
*Creates a local SQLite database (`db_staging.sqlite3`), creates the superuser `admin` with password `admin123`, and generates a valid sample file `sample_document.pdf`.*

### Step 3: Start the Server
```bash
poetry run python manage.py runserver 8000
```

### Step 4: Open the Web GUI in Your Browser
* **Public Password Request Portal**: Open [http://127.0.0.1:8000/freedec/](http://127.0.0.1:8000/freedec/) in your browser.
* **Public Document Decryption Portal (.enc)**: Open [http://127.0.0.1:8000/freedec/descifrar/](http://127.0.0.1:8000/freedec/descifrar/) in your browser.
* **Admin Upload Portal**: Log in at [http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/) (`admin` / `admin123`) and navigate to [http://127.0.0.1:8000/freedec/admin-upload/](http://127.0.0.1:8000/freedec/admin-upload/).

> [!TIP]
> **Clear Settings & Local Testing Presetting**: The application runs directly without requiring a `.env` file.
> - `config/settings.py`: Provides the **generic setting** in plain clear Python (zero `.env` dependency and no private hardcoded credentials).
> - `config/presettings.py`: Holds the local test presetting with staging database and real SMTP (**Ethereal Email**) to inspect dispatched emails in real time at [https://ethereal.email/messages](https://ethereal.email/messages) by running `python manage.py runserver --settings=config.presettings`.

### Step 5: Run Automated CLI Demo (Optional)
In another terminal:
```bash
poetry run python scripts/demo_flow.py
```

---

## 4. The 4 Installation Options into an Existing Project

If you already have an existing Django project, you can integrate `freedec` in any of these 4 ways:

### Option 1: Copy the `freedec/` Folder (Simplest & Most Direct)
* **What to copy?**: **ONLY the `freedec/` folder**.
* **What NOT to copy?**: **DO NOT copy `config/` or root `manage.py`** (your project already has its own).
* **Command to install requirements**:
  In your host project directory:
  ```bash
  poetry add cryptography djangorestframework
  ```

#### Visual Directory Comparison:
```text
Your Project BEFORE copying:             Your Project AFTER copying:
----------------------------             ---------------------------
my_project/                              my_project/
├── manage.py                            ├── manage.py
├── my_config/                           ├── my_config/
│   ├── settings.py                      │   ├── settings.py  <-- Add 4 lines
│   ├── urls.py                          │   ├── urls.py      <-- Add 1 line
│   └── wsgi.py                          │   └── wsgi.py
                                         └── freedec/         <-- Only copy this!
                                             ├── models.py
                                             ├── views.py
                                             ├── templates/
                                             └── ...
```

---

### Option 2: As a Direct Git Dependency via Poetry (Best for Teams)
```bash
poetry add git+https://github.com/jrubioh1/Freedec.git
```

---

### Option 3: Local Editable Path via Poetry (Monorepos & Active Development)
```bash
poetry add --editable /absolute/path/to/Freedec
```

---

### Option 4: Via PyPI or Private Package Registry
```bash
# In Freedec repository:
poetry build
poetry publish

# In your host project:
poetry add freedec
```

---

## 5. Step-by-Step Integration Checklist (Line by Line)

Follow these 6 numbered steps in your existing Django project:

### Step 1: Generate Master Fernet Key
In your terminal:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

### Step 2: Edit Your `settings.py` File
```python
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# 1. Add 'rest_framework' and 'freedec.apps.FreedecConfig'
INSTALLED_APPS = [
    # Existing apps...
    'rest_framework',
    'freedec.apps.FreedecConfig',
]

# 2. Configure master key generated in Step 1
FREEDEC_FERNET_KEY = os.environ.get("FREEDEC_FERNET_KEY", "YOUR_KEY_HERE==")

# 3. Maximum file size (default: 50 MB)
FREEDEC_MAX_FILE_SIZE = 50 * 1024 * 1024

# 4. MEDIA settings
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# 5. Email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
DEFAULT_FROM_EMAIL = 'no-reply@yourdomain.com'

# 6. DRF Rate Limiting
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': ['rest_framework.throttling.AnonRateThrottle'],
    'DEFAULT_THROTTLE_RATES': {'anon': '5/minute'},
}
```

---

### Step 3: Edit Your Main `urls.py` File
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

---

### Step 4: Run Database Migrations
```bash
poetry run python manage.py makemigrations freedec
poetry run python manage.py migrate
```

---

### Step 5: Create Superuser (if needed)
```bash
poetry run python manage.py createsuperuser
```

---

### Step 6: Start Your Server
```bash
poetry run python manage.py runserver
```

---

## 6. How the Web GUI Works and How to Use It

### A. Admin Upload Portal (`http://localhost:8000/freedec/admin-upload/` or Django Admin)
1. Log in first at `/admin/` (or your project's configured Django admin URL).
2. You can register documents either from `/admin/` (**Encrypted Documents -> Add**) or from `/freedec/admin-upload/`.
3. Select your document in an authorized format (**PDF, LibreOffice .odt/.ods, or MS Office .docx/.xlsx**).
4. Optionally enter a custom decryption password, or leave it blank to automatically generate a cryptographically strong 24-character password.
5. Enter authorized recipient emails (interactive `+` button available to add multiple addresses).
6. Click **Encrypt and Register** (or **Save** in Django Admin).
7. **Result**:
   * **Automatic Credentials Receipt Download**: The browser immediately downloads `<original_filename>_credenciales.txt` containing the SHA-256 hash, secret access code, assigned password, authorized emails, and direct access links, allowing local storage without server plaintext persistence.
   * The screen displays the **Access Code (`access_code`)** with quick-copy button and the **Assigned Password**.
   * A direct download button for the encrypted file `<original_filename>.enc`.

---

### B. Public Password Request Portal (`http://localhost:8000/freedec/`)
1. The user navigates to `http://localhost:8000/freedec/`.
2. Uploads their file copy (either the original file or the `.enc` encrypted container).
3. Pastes the secret access code provided by the issuer.
4. Enters their authorized email address.
5. Clicks **Request Password**.
6. **Result**: A uniform, neutral confirmation message is displayed (preventing user or document enumeration). If the data matches and the email is authorized:
   * The system immediately emails the password to the recipient, **explicitly citing the document name** and a direct link to the decryption portal.
   * The access event is recorded in the `DocumentAccessLog` audit table, incrementing `access_count` and recording the last access timestamp and client IP.

---

### C. Public Document Decryption Portal (`http://localhost:8000/freedec/descifrar/`)
*How to turn the `.enc` file back into the original document?*
1. The user navigates to `http://localhost:8000/freedec/descifrar/` (or clicks **🔓 Descifrar Archivo (.enc)** in the navbar).
2. Uploads the `.enc` file.
3. Pastes the password received in their email.
4. Clicks **Descifrar y Descargar Archivo Original**.
5. **Result**: The system decrypts the container in memory with Fernet and triggers an instant download of the original file with its exact name and extension (`document.pdf`, `contract.docx`, etc.).

---

### D. Document Deletion & Physical Disk Erasure (Right to Erasure / GDPR)
When deleting a registered document:
* **Automated `post_delete` Signal**: Deleting a record via Django Admin or ORM triggers automatic unlinking and physical deletion of the `.enc` file in `MEDIA_ROOT`.
* **Direct Admin Button**: The document table at `/admin/freedec/encrypteddocument/` provides an inline `🗑️ Eliminar` button on each row.
* **CLI Management Command**:
  ```bash
  # List existing documents
  poetry run python manage.py delete_document --list

  # Delete a specific document by name or hash
  poetry run python manage.py delete_document balance_anual.pdf

  # Delete all database records and physical (.enc) files
  poetry run python manage.py delete_document --all
  ```

---

### E. Apache Deployment & Multi-App Compatibility (Same Domain)
Freedec is engineered to run seamlessly alongside other applications on the same Apache server:
* **Isolated Namespace**: All routes reside under `/freedec/` (e.g. `http://domain.com/freedec/`), avoiding conflicts with the root domain `/` or other apps.
* **Dynamic Resolution with SCRIPT_NAME**: HTML templates use `{% url 'freedec:gui-public-request' %}` and `{% url 'freedec:gui-public-decrypt' %}`, adapting dynamically to subfolders (`WSGIScriptAlias /freedec` or `ProxyPass`).
* **Decoupled Admin Integration**: Receipts and links to Django admin dynamically use `reverse('admin:index')`, respecting whatever admin URL the host project defines.

---

### F. Command Line Decryption (CLI)
For system administrators, automated pipelines, or offline recovery:
```bash
poetry run python manage.py decrypt_document path/to/file.enc --password "YourPassword" --output recovered_document.pdf
```

---

## 7. REST API Endpoints

### 1. Admin Upload (`POST /freedec/api/admin/upload/`)
```bash
curl -X POST http://127.0.0.1:8000/freedec/api/admin/upload/ \
  -u admin:admin123 \
  -F "original_file=@document.pdf" \
  -F "plain_password=SecretPassword#2026!" \
  -F 'allowed_emails=["auditor@corp.com"]'
```

### 2. Public Password Request (`POST /freedec/api/public/request-password/`)
```bash
curl -X POST http://127.0.0.1:8000/freedec/api/public/request-password/ \
  -F "file=@document.pdf" \
  -F "access_code=SECRET_ACCESS_CODE" \
  -F "email=auditor@corp.com"
```

---

## 8. Production MEDIA Configuration (Nginx & Apache)

> [!WARNING]
> **Why NEVER use `static()` in production?**  
> When `DEBUG = False`, Django disables `static()` for performance and security. Serving large files via Python would freeze workers. Reverse proxies (Nginx or Apache) must serve `/media/` directly from the OS kernel.

### Option A: **Nginx** Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    location /media/ {
        alias /var/www/your_project/media/;
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

### Option B: **Apache** Configuration (`httpd` / `mod_wsgi`)
```apache
<VirtualHost *:443>
    ServerName yourdomain.com

    Alias /media/ /var/www/your_project/media/

    <Directory /var/www/your_project/media>
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

    WSGIDaemonProcess your_project python-home=/var/www/your_project/.venv python-path=/var/www/your_project
    WSGIProcessGroup your_project
    WSGIScriptAlias / /var/www/your_project/config/wsgi.py
</VirtualHost>
```

---

## 9. Frequently Asked Questions (FAQ / Troubleshooting)

### Error: `ImproperlyConfigured: Falta la configuración FREEDEC_FERNET_KEY`?
* **Cause**: Master key is missing in `settings.py`.
* **Fix**: Generate one via `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` and set it in `settings.py`.

### 404 Error downloading encrypted `.enc` file?
* **In development**: Missing `urlpatterns += static(settings.MEDIA_URL, ...)` in `urls.py`.
* **In production**: Missing `/media/` alias in your Nginx or Apache configuration.

### Password email not received?
* **In default development / staging**: You have `EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'`. Passwords print to the console terminal running Django.
* **Fix**: Configure real SMTP credentials in a `.env` file (copying `.env.example`). You can test your SMTP delivery immediately with:
  ```bash
  poetry run python manage.py test_smtp your-email@gmail.com
  ```

### What happens when an encrypted document record is deleted?
* **Guaranteed Physical File Deletion**: A `post_delete` signal listener guarantees that whenever an `EncryptedDocument` record is deleted (from Django Admin single view, bulk actions, or ORM `QuerySet.delete()`), the underlying physical `.enc` file in `media_staging/encrypted_docs/` is immediately removed from disk for strict GDPR and privacy compliance.

### Error: `Tipo de archivo no permitido`?
* **Cause**: Only **PDF, LibreOffice (.odt, .ods, .odp, .odg), and MS Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt)** documents are allowed. Plain `.txt`, executables `.exe`, and scripts `.sh` are rejected.
