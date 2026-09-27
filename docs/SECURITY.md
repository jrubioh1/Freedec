# Matriz de Ciberseguridad y Prevención OWASP Top 10 / Cybersecurity & OWASP Top 10 Matrix

<p align="center">
  <a href="#seccion-espanol"><b>🇪🇸 Leer en Español</b></a> &nbsp;&nbsp;|&nbsp;&nbsp; 
  <a href="#section-english"><b>🇬🇧 Read in English</b></a>
</p>

---

<a id="seccion-espanol"></a>
# 🇪🇸 Español

Este documento expone las medidas de ciberseguridad, las decisiones criptográficas, la validación multinivel de formatos de archivo, la política de destrucción física por trituración (**Zeroization/Shredding**) y la **matriz de cumplimiento contra el OWASP Top 10 Web Application Security Risks**.

---

## 1. Validación Estricta de Formatos Permitidos (Anti-Malware & Anti-Spoofing)

La aplicación restinge de forma estricta los archivos procesados exclusivamente a **PDF, LibreOffice y Microsoft Office**. Para evitar técnicas de evasión o renombrado malicioso de ejecutables (`evil.exe -> evil.pdf`), el validador `freedec/validators.py` aplica una **estrategia de validación multinivel**:

1. **Lista Blanca de Extensiones**:
   - **PDF**: `.pdf`
   - **LibreOffice / OpenDocument Format (ODF)**: `.odt` (Writer), `.ods` (Calc), `.odp` (Impress), `.odg` (Draw).
   - **Microsoft Office Moderno (OpenXML)**: `.docx`, `.xlsx`, `.pptx`.
   - **Microsoft Office Clásico (OLE2 Binary)**: `.doc`, `.xls`, `.ppt`.
2. **Inspección de Firmas Binarias (Magic Bytes)**:
   - Los archivos PDF deben comenzar estrictamente con `b"%PDF-"`.
   - Los archivos Office clásicos deben comenzar con el identificador OLE2 `b"\xd0\xcf\x11\xe0"`.
   - Los archivos Office modernos y LibreOffice deben comenzar con la firma de cabecera ZIP `b"PK\x03\x04"`.
3. **Inspección Estructural Profunda (Anti-Zip Bomb & Anti-Spoofing)**:
   - Para formatos basados en ZIP (`.docx`, `.odt`, etc.), el archivo se analiza en memoria:
     - **Defensa Anti-Zip Bomb**: Se comprueba el número de entradas internas (`<= 500`) y el tamaño total descomprimido (`<= 100 MB`).
     - **Verificación de Estructura LibreOffice**: Se exige la presencia del archivo interno `mimetype` con contenido `application/vnd.oasis.opendocument...`.
     - **Verificación de Estructura MS Office**: Se exige la presencia obligatoria de `[Content_Types].xml`.

---

## 2. Matriz de Cumplimiento OWASP Top 10 (2021)

| Categoría OWASP | Vector de Riesgo | Mitigación Implementada en Freedec |
| :--- | :--- | :--- |
| **A01:2021 – Broken Access Control** | Acceso no autorizado a subidas o descarga de documentos sin permiso. | - Subida y administración centralizada en Django Admin, protegida por autenticación de staff/superusuario y permisos granulares (`can_audit_download`).<br>- **Cero Transporte del Binario por el Cliente**: El usuario no sube el `.enc`; el localizador oficial es exclusivamente el hash SHA-256 (64 hex).<br>- Eliminación de IDORs: búsqueda unívoca por `file_hash`.<br>- **Descarga administrativa preservada (Audit Bypass)**: solo disponible para staff con permiso específico, auditada con `admin_descarga_preservada`. |
| **A02:2021 – Cryptographic Failures** | Claves débiles, algoritmos obsoletos o almacenamiento de secretos en claro. | - Cifrado simétrico autenticado (AEAD) con **AES-128-CBC + HMAC-SHA256 (Fernet)**.<br>- **Zero Human-Readable Passwords**: Clave Maestra de Datos (DEK) única generada con `Fernet.generate_key()` y cifrada en reposo con la clave de servidor `settings.FREEDEC_FERNET_KEY`. Ningún humano gestiona claves en claro.<br>- **Comparación en Tiempo Constante**: Validación de OTP con `secrets.compare_digest`.<br>- **Caducidad estricta y bloqueo**: OTP expira a los 15 minutos y se bloquea al 3er intento fallido.<br>- Validación obligatoria de `FREEDEC_FERNET_KEY` (32 bytes base64 url-safe) al arranque en `apps.py`. |
| **A03:2021 – Injection** | Inyección SQL, inyección de cabeceras de correo (CRLF) o subida de scripts maliciosos. | - **SQL Injection**: Django ORM parametrizado nativo.<br>- **CRLF / Email Header Injection**: Función `validate_safe_email` que rechaza retornos de carro (`\r`, `\n`, `%0a`, `%0d`) y captura de `BadHeaderError`.<br>- **Anti-Path Traversal**: Sanitización estricta con `os.path.basename` y almacenamiento en disco en rutas parametrizadas `encrypted_docs/%Y/%m/`. |
| **A04:2021 – Insecure Design** | Ataques de enumeración de recursos o canal lateral por temporización (Timing Attacks). | - **Mitigación Anti-Timing & Anti-Enumeración**: Ejecuta hash simulado PBKDF2 cuando el hash o el correo no existen/no están autorizados, devolviendo una respuesta neutra uniforme (`HTTP 200`).<br>- **Gestión Segura Post-Consumo**: Si un documento ya fue consumido (`is_consumed == True`), no se furan datos ni binarios; se notifica por correo al solicitante indicando quién lo retiró (`consumed_by`) y cuándo (`consumed_at`), registrando `intento_post_consumo`. |
| **A05:2021 – Security Misconfiguration** | Cabeceras HTTP inseguras, modo Debug activo o claves ausentes. | - Cabeceras de seguridad activas en settings (`SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS = 'DENY'`).<br>- El método `ready()` de `FreedecConfig` detiene el arranque con `ImproperlyConfigured` si `FREEDEC_FERNET_KEY` no es válida o está ausente. |
| **A06:2021 – Vulnerable and Outdated Components** | Uso de dependencias obsoletas o con vulnerabilidades. | - Gestión de dependencias bloqueadas mediante **Poetry** (`poetry.lock` / `pyproject.toml`).<br>- Dependencias modernas: `django = "^5.2"`, `djangorestframework = "^3.15"`, `cryptography = "^43.0"`. |
| **A07:2021 – Identification & Authentication Failures** | Ataques de fuerza bruta contra contraseñas o tokens. | - **Eliminación total de contraseñas humanas**: sustituidas por verificación OTP de 6 dígitos generada con `secrets.choice("0123456789")`.<br>- Límite de 3 intentos fallidos con revocación permanente (`token.is_used = True`) y registro `otp_invalido_bloqueado`.<br>- Caducidad forzada a 15 minutos e invalidación inmediata tras el canje. |
| **A08:2021 – Software & Data Integrity Failures** | Manipulación de archivos cifrados o datos no confiables. | - Integridad garantizada por Fernet: cualquier bit modificado en disco invalida el HMAC y rechaza el descifrado.<br>- Comprobación de integridad SHA-256 en runtime mediante lectura en streaming de 64 KB.<br>- Cero deserialización insegura (`pickle`, `yaml.load`). |
| **A09:2021 – Security Logging & Monitoring Failures** | Falta de visibilidad de ataques o filtración de credenciales en logs. | - **Auditoría Legal Completa**: Modelo `DocumentAccessLog` con registro inmutable de fecha, email solicitante, acción (`solicitud_otp`, `otp_enviado`, `descifrado_exitoso_burn`, `intento_post_consumo`, `otp_invalido_bloqueado`, `admin_descarga_preservada`), IP remota y User-Agent.<br>- **Regla de Cero Filtraciones**: Nunca se registran claves ni códigos OTP en claro en los logs. |
| **A10:2021 – Server-Side Request Forgery (SSRF)** | Peticiones HTTP arbitrarias iniciadas por el servidor. | - La aplicación no realiza peticiones HTTP salientes hacia URLs externas no confiables. |
| **Privacidad & GDPR / Zeroization (Burn-After-Read)** | Archivos confidenciales huérfanos o recuperables forensemente tras su canje. | - **Trituración Segura Física (Shredding/Zeroization)**: Al primer canje exitoso, el archivo en disco es sobrescrito con bytes aleatorios (`os.urandom`), forzando escritura a almacenamiento físico con `flush()` y `os.fsync()`, antes de llamar a `os.remove()`.<br>- **Borrado en Cascada**: Señal `post_delete` conectada a `EncryptedDocument` que tritura físicamente el archivo del disco ante eliminaciones administrativas. |

---
---

<a id="section-english"></a>
# 🇬🇧 English

This document outlines the cryptographic decisions, multi-level file validation, physical destruction policy (**Zeroization/Shredding**), and the **OWASP Top 10 Web Application Security Risks compliance matrix**.

---

## 1. Strict Allowed Formats Validation (Anti-Malware & Anti-Spoofing)

The application strictly limits processed files to **PDF, LibreOffice, and Microsoft Office**. The validator `freedec/validators.py` enforces a multi-tier defense:
1. **Extension Whitelist**: `.pdf`, `.odt`, `.ods`, `.odp`, `.odg`, `.docx`, `.xlsx`, `.pptx`, `.doc`, `.xls`, `.ppt`.
2. **Binary Signature Inspection (Magic Bytes)**: Validates PDF (`%PDF-`), OLE2 (`\xd0\xcf\x11\xe0`), and ZIP (`PK\x03\x04`).
3. **Deep Structural Inspection**: Anti-Zip Bomb limits (max 500 entries, max 100 MB uncompressed), and mandatory structure check (`mimetype` for ODF, `[Content_Types].xml` for OpenXML).

---

## 2. OWASP Top 10 (2021) Compliance Matrix

| OWASP Category | Risk Vector | Mitigation Implemented in Freedec |
| :--- | :--- | :--- |
| **A01:2021 – Broken Access Control** | Unauthorized access to upload or retrieve files. | - Centralized Django Admin upload with granular permissions (`can_audit_download`).<br>- **Zero Client Binary Transport**: Client never uploads `.enc`; uses strictly SHA-256 hash.<br>- IDOR elimination: unique document lookup by `file_hash`.<br>- Preserved administrative download for auditors (`admin_descarga_preservada`). |
| **A02:2021 – Cryptographic Failures** | Weak keys, obsolete ciphers, or plaintext secret storage. | - Authenticated encryption (AEAD) with **AES-128-CBC + HMAC-SHA256 (Fernet)**.<br>- **Zero Human-Readable Passwords**: Random unique DEK protected by `FREEDEC_FERNET_KEY`.<br>- Constant-time OTP comparison with `secrets.compare_digest`.<br>- Strict 15-minute expiration and 3-attempt lockout.<br>- Mandatory startup key validation in `apps.py`. |
| **A03:2021 – Injection** | SQL, CRLF, or path traversal injection. | - Parameterized Django ORM queries.<br>- `validate_safe_email` strictly blocks CRLF characters (`\r`, `\n`, `%0a`, `%0d`).<br>- `os.path.basename` prevents directory traversal. |
| **A04:2021 – Insecure Design** | Side-channel timing attacks and resource enumeration. | - **Anti-Timing & Anti-Enumeración**: Simulated PBKDF2 calculation for non-existent records or unauthorized emails with uniform neutral response.<br>- **Post-Consumption Notice**: Dispatches email to requester stating who consumed the file and when, logging `intento_post_consumo`. |
| **A05:2021 – Security Misconfiguration** | Insecure headers or missing configuration. | - Recommended security headers configured.<br>- `FreedecConfig.ready()` halts startup if `FREEDEC_FERNET_KEY` is missing or invalid. |
| **A06:2021 – Vulnerable and Outdated Components** | Vulnerable dependencies. | - Locked dependencies with **Poetry** (`django ^5.2`, `cryptography ^43.0`). |
| **A07:2021 – Identification & Authentication Failures** | Brute-force attacks against access mechanisms. | - **Zero human passwords**: replaced by 6-digit cryptographic OTP (`secrets.choice`).<br>- 3-attempt lock with permanent revocation and `otp_invalido_bloqueado` logging. |
| **A08:2021 – Software & Data Integrity Failures** | Ciphertext or storage tampering. | - Fernet HMAC-SHA256 integrity verification.<br>- SHA-256 streaming verification in 64 KB chunks. |
| **A09:2021 – Security Logging & Monitoring Failures** | Insufficient audit trail or credential leakage. | - **Comprehensive Audit Trail**: `DocumentAccessLog` records all actions without storing plaintext secrets. |
| **A10:2021 – Server-Side Request Forgery (SSRF)** | Malicious outbound requests. | - Server does not make arbitrary outbound requests. |
| **Privacy & GDPR / Zeroization (Burn-After-Read)** | Orphaned confidential data recoverable forensically. | - **Secure Physical Shredding (Zeroization)**: Encrypted file on disk is overwritten with `os.urandom(file_size)`, flushed and synced via `os.fsync()`, and deleted on first successful redemption. |
