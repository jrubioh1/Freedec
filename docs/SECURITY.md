# Matriz de Ciberseguridad y Prevención OWASP Top 10 / Cybersecurity & OWASP Top 10 Matrix

<p align="center">
  <a href="#seccion-espanol"><b>🇪🇸 Leer en Español</b></a> &nbsp;&nbsp;|&nbsp;&nbsp; 
  <a href="#section-english"><b>🇬🇧 Read in English</b></a>
</p>

---

<a id="seccion-espanol"></a>
# 🇪🇸 Español

Este documento expone en profundidad las decisiones criptográficas, la validación estricta de formatos de archivo (PDF, LibreOffice, MS Office), la política de destrucción física **Burn-After-Read** y la **matriz de cumplimiento contra el OWASP Top 10 Web Application Security Risks**.

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
| **A01:2021 – Broken Access Control** | Acceso no autorizado a subidas o descarga de documentos sin permiso. | - Subida y administración centralizada en Django Admin, protegida por autenticación nativa de staff/superusuario y control de acceso basado en roles.<br>- Eliminación de IDORs: no existen IDs secuenciales; el identificador lógico es el hash SHA-256 del contenido que el usuario debe poseer.<br>- Panel Django Admin con campos sensibles configurados como `readonly_fields`.<br>- **Descarga administrativa protegida (Audit Bypass)**: solo disponible para usuarios staff con permisos, auditada con `admin_inspeccion_preservada`. |
| **A02:2021 – Cryptographic Failures** | Claves débiles, algoritmos obsoletos o almacenamiento de secretos en claro. | - Cifrado simétrico autenticado (AEAD) con **AES-128-CBC + HMAC-SHA256 (Fernet)**.<br>- **Arquitectura DEK Multi-Usuario**: Clave Maestra de Datos (DEK) única generada con `Fernet.generate_key()` y cifrada individualmente por destinatario en sobres digitales (`user_envelopes`).<br>- **Zero-Knowledge de Tokens**: En la base de datos **NUNCA se guarda el token en texto plano**; se almacena su hash **SHA-256**.<br>- **Caducidad estricta**: Los tokens y OTPs expiran irrevocablemente a los 15 minutos.<br>- Validación obligatoria de la clave maestra Fernet al arranque en `apps.py`. |
| **A03:2021 – Injection** | Inyección SQL, inyección de cabeceras de correo (CRLF) o subida de scripts maliciosos. | - **SQL Injection**: Django ORM parametrizado nativo.<br>- **CRLF / Email Header Injection**: Función `validate_safe_email` que rechaza retornos de carro (`\r`, `\n`, `%0a`, `%0d`) y captura de `BadHeaderError`.<br>- **Anti-Path Traversal**: El nombre original se sanea rigurosamente con `os.path.basename` y se almacena empaquetado en disco como `<original_filename>.enc`, imposibilitando la escritura fuera de `encrypted_docs/`. |
| **A04:2021 – Insecure Design** | Ataques de enumeración de recursos o canal lateral por temporización (Timing Attacks). | - Respuesta HTTP neutra uniforme (`HTTP 200` con mensaje genérico preventivo), impidiendo que un atacante deduzca la existencia de archivos o emails registrados.<br>- **Gestión Segura Post-Consumo**: Si un documento ya fue consumido (`is_consumed == True`), no se furan datos ni binarios; se notifica por correo al solicitante indicando quién lo consumió (`consumed_by`) y cuándo (`consumed_at`). |
| **A05:2021 – Security Misconfiguration** | Cabeceras HTTP inseguras, modo Debug activo o permisos laxos. | - Configuración recomendada de cabeceras en settings (`SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS = 'DENY'`).<br>- La aplicación detiene el arranque en producción si `FREEDEC_FERNET_KEY` no está configurada o es inválida. |
| **A06:2021 – Vulnerable and Outdated Components** | Uso de dependencias obsoletas o con CVEs conocidos. | - Gestión de dependencias bloqueadas mediante **Poetry** (`pyproject.toml`).<br>- Dependencias modernas y mantenidas: `django = "^5.1"`, `djangorestframework = "^3.15"`, `cryptography = "^43.0"`. |
| **A07:2021 – Identification & Authentication Failures** | Ataques de fuerza bruta contra contraseñas o códigos estáticos. | - **Eliminación total de contraseñas estáticas**: sustituidas por Enlace Mágico temporal y código OTP de 6 dígitos.<br>- Caducidad forzada a 15 minutos e invalidación inmediata tras el primer uso (`is_used = True`).<br>- Rate limiting en el endpoint público mediante `AnonRateThrottle` en DRF. |
| **A08:2021 – Software & Data Integrity Failures** | Manipulación de archivos cifrados o datos no confiables. | - Integridad garantizada por Fernet: cualquier bit modificado en disco invalida el HMAC y rechaza el descifrado.<br>- Comprobación de integridad binaria SHA-256 en runtime tanto del original (`file_hash`) como del cifrado (`encrypted_file_hash`).<br>- No se utiliza deserialización insegura (`pickle`, `yaml.load`). |
| **A09:2021 – Security Logging & Monitoring Failures** | Falta de visibilidad de ataques o filtración de credenciales en logs. | - **Auditoría Completa en Base de Datos**: Modelo `DocumentAccessLog` con registro inmutable de fecha, email solicitante, acción (`solicitud_acceso`, `descifrado_completado_burn`, `intento_post_consumo`, `admin_inspeccion_preservada`), IP remota y User-Agent.<br>- **Trazabilidad en Tiempo Real**: Métricas `access_count`, `last_accessed_at` y `last_accessed_by` en cada documento.<br>- **Regla de Cero Filtraciones**: **NUNCA** se registran tokens en texto claro ni secretos en los logs. |
| **A10:2021 – Server-Side Request Forgery (SSRF)** | Peticiones HTTP arbitrarias iniciadas por el servidor. | - La aplicación no realiza peticiones HTTP salientes hacia URLs proporcionadas por usuarios. Todos los archivos se procesan directamente mediante streams locales `multipart/form-data`. |
| **Privacidad & GDPR / Burn-After-Read** | Archivos confidenciales huérfanos tras ser consumidos o eliminados. | - **Política Estricta Burn-After-Read**: En cuanto un usuario final autorizado descarga el documento, el archivo físico `.enc` se destruye inmediatamente de disco (`encrypted_file.delete(save=False)`).<br>- **Eliminación Física en Cascada**: Señal `post_delete` conectada a `EncryptedDocument` que borra físicamente el archivo del disco ante eliminaciones administrativas. |

---
---

<a id="section-english"></a>
# 🇬🇧 English

This document details the cryptographic design decisions, strict document format enforcement (PDF, LibreOffice, MS Office), the **Burn-After-Read** destruction policy, and the **OWASP Top 10 Web Application Security Risks compliance matrix**.

---

## 1. Strict Document Format Validation (Anti-Malware & Anti-Spoofing)

The application strictly limits processed files to **PDF, LibreOffice, and Microsoft Office**. To prevent extension spoofing or disguised executables (`evil.exe -> evil.pdf`), the validator `freedec/validators.py` enforces a **multi-layer validation strategy**:

1. **Extension Whitelist**:
   - **PDF**: `.pdf`
   - **LibreOffice / OpenDocument Format (ODF)**: `.odt` (Writer), `.ods` (Calc), `.odp` (Impress), `.odg` (Draw).
   - **Modern Microsoft Office (OpenXML)**: `.docx`, `.xlsx`, `.pptx`.
   - **Legacy Microsoft Office (OLE2 Binary)**: `.doc`, `.xls`, `.ppt`.
2. **Binary Signature Inspection (Magic Bytes)**:
   - PDF files must strictly start with `b"%PDF-"`.
   - Legacy Office files must start with the OLE2 identifier `b"\xd0\xcf\x11\xe0"`.
   - Modern Office and LibreOffice files must start with the ZIP header `b"PK\x03\x04"`.
3. **Deep Structural Inspection (Anti-Zip Bomb & Anti-Spoofing)**:
   - For ZIP-based formats (`.docx`, `.odt`, etc.), the file is inspected in memory:
     - **Anti-Zip Bomb Defense**: Maximum 500 internal entries and maximum 100 MB total uncompressed size.
     - **LibreOffice Structure Verification**: Requires the presence of the root `mimetype` file containing `application/vnd.oasis.opendocument...`.
     - **MS Office Structure Verification**: Requires the presence of `[Content_Types].xml`.

---

## 2. OWASP Top 10 (2021) Compliance Matrix

| OWASP Category | Risk Vector | Mitigation Implemented in Freedec |
| :--- | :--- | :--- |
| **A01:2021 – Broken Access Control** | Unauthorized uploads or unauthorized document key retrieval. | - Administration strictly centralized in Django Admin, protected by native Django staff/superuser authentication and model permissions.<br>- Total IDOR elimination: no sequential IDs; lookup is performed strictly by SHA-256 content hash.<br>- Django Admin panel configured with sensitive fields as `readonly_fields`.<br>- **Preserved administrative download (Audit Bypass)**: accessible only to staff users with change permissions, logged as `admin_inspeccion_preservada`. |
| **A02:2021 – Cryptographic Failures** | Weak keys, obsolete ciphers, or plaintext secret storage. | - Authenticated symmetric encryption (AEAD) with **AES-128-CBC + HMAC-SHA256 (Fernet)**.<br>- **Multi-User DEK Architecture**: A unique Data Encryption Key (DEK) is generated with `Fernet.generate_key()` and encrypted per recipient inside digital envelopes (`user_envelopes`).<br>- **Zero-Knowledge Token Storage**: Plaintext tokens are **NEVER stored in the database**; only **SHA-256 hashes** are kept.<br>- **Strict 15-Minute Expiration**: All access tokens and OTP codes irrevocably expire in 15 minutes.<br>- Mandatory startup key check in `apps.py`. |
| **A03:2021 – Injection** | SQL Injection, CRLF email header injection, or path traversal. | - **SQL Injection**: Parameterized queries via native Django ORM.<br>- **CRLF / Email Header Injection**: `validate_safe_email` rejects `\r`, `\n`, `%0a`, `%0d`, and catches `BadHeaderError`.<br>- **Anti-Path Traversal**: Original file name is strictly sanitized with `os.path.basename` and stored as `<original_filename>.enc`, completely preventing directory traversal attacks. |
| **A04:2021 – Insecure Design** | Document enumeration or side-channel Timing Attacks. | - Uniform neutral response (`HTTP 200` with generic safe text) prevents probing resource existence.<br>- **Secure Post-Consumption Handling**: If a document has already been consumed (`is_consumed == True`), no binary data leaks; an email notification is dispatched to the requester stating who consumed it (`consumed_by`) and when (`consumed_at`). |
| **A05:2021 – Security Misconfiguration** | Insecure headers, active debug mode, or default keys. | - Recommended security headers configured (`SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS = 'DENY'`).<br>- Startup halts if `FREEDEC_FERNET_KEY` is missing or invalid in production. |
| **A06:2021 – Vulnerable and Outdated Components** | Obsolete dependencies with known CVEs. | - Locked dependencies managed via **Poetry** (`pyproject.toml`).<br>- Up-to-date and actively maintained dependencies: `django = "^5.1"`, `djangorestframework = "^3.15"`, `cryptography = "^43.0"`. |
| **A07:2021 – Identification & Authentication Failures** | Brute-force attacks against access codes or passwords. | - **Complete removal of static passwords**: replaced by dynamic Proof-of-Possession via 15-minute Magic Link and 6-digit OTP.<br>- One-time usage enforcement (`is_used = True`).<br>- Perimeter rate limiting via `AnonRateThrottle` on the public endpoint. |
| **A08:2021 – Software & Data Integrity Failures** | Tampering with stored encrypted files or untrusted data. | - Fernet HMAC integrity: altering any bit on disk causes decryption failure.<br>- Runtime SHA-256 verification of both unencrypted original (`file_hash`) and encrypted storage (`encrypted_file_hash`).<br>- No unsafe deserialization (`pickle`, `yaml.load`). |
| **A09:2021 – Security Logging & Monitoring Failures** | Lack of attack visibility or credential leakage in log files. | - **Comprehensive Database Audit Logging**: Inmutable `DocumentAccessLog` records timestamp, requester email, action (`solicitud_acceso`, `descifrado_completado_burn`, `intento_post_consumo`, `admin_inspeccion_preservada`), remote IP, and User-Agent.<br>- **Real-time Traceability**: `access_count`, `last_accessed_at`, and `last_accessed_by` tracked on every document.<br>- **Zero-Leakage Policy**: **NEVER** log plaintext tokens or secrets in log files. |
| **A10:2021 – Server-Side Request Forgery (SSRF)** | Malicious outbound requests initiated by the server. | - The application never performs outbound requests to user-supplied URLs. All files are handled via local `multipart/form-data` streams. |
| **Privacy & GDPR / Burn-After-Read** | Orphaned confidential encrypted files left on disk after consumption. | - **Strict Burn-After-Read Policy**: As soon as an authorized recipient downloads the document, the physical `.enc` file is permanently deleted from storage (`encrypted_file.delete(save=False)`).<br>- **Cascading Physical Erasure**: `post_delete` signal hooked to `EncryptedDocument` deletes physical files upon manual database record deletion. |
