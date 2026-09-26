# Matriz de Ciberseguridad y Prevención OWASP Top 10 / Cybersecurity & OWASP Top 10 Matrix

<p align="center">
  <a href="#seccion-espanol"><b>🇪🇸 Leer en Español</b></a> &nbsp;&nbsp;|&nbsp;&nbsp; 
  <a href="#section-english"><b>🇬🇧 Read in English</b></a>
</p>

---

<a id="seccion-espanol"></a>
# 🇪🇸 Español

Este documento expone en profundidad las decisiones criptográficas, la validación estricta de formatos de archivo (PDF, LibreOffice, MS Office) y la **matriz de cumplimiento contra el OWASP Top 10 Web Application Security Risks**.

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
| **A01:2021 – Broken Access Control** | Acceso no autorizado a subidas o descarga de documentos sin permiso. | - Subida y administración centralizada en Django Admin, protegida por autenticación nativa de staff/superusuario y control de acceso basado en roles.<br>- Eliminación de IDORs: no existen IDs secuenciales; el identificador lógico es el hash SHA-256 del contenido que el usuario debe poseer.<br>- Panel Django Admin con campos sensibles configurados como `readonly_fields`. |
| **A02:2021 – Cryptographic Failures** | Claves débiles, algoritmos obsoletos o almacenamiento de secretos en claro. | - Cifrado simétrico autenticado (AEAD) con **AES-128-CBC + HMAC-SHA256 (Fernet)**.<br>- Almacenamiento **Zero-Knowledge** del `access_code` hasheado con **PBKDF2-SHA256**.<br>- Generación de claves con CSPRNG (`secrets.token_urlsafe(32)` con 256 bits de entropía).<br>- Validación obligatoria de la clave maestra Fernet al arranque en `apps.py`. |
| **A03:2021 – Injection** | Inyección SQL, inyección de cabeceras de correo (CRLF) o subida de scripts maliciosos. | - **SQL Injection**: Django ORM parametrizado nativo.<br>- **CRLF / Email Header Injection**: Función `validate_safe_email` que rechaza retornos de carro (`\r`, `\n`, `%0a`, `%0d`) y captura de `BadHeaderError`.<br>- **Anti-Path Traversal**: El nombre original se sanea rigurosamente con `os.path.basename` y se almacena empaquetado en disco como `<original_filename>.enc`, imposibilitando la escritura fuera de `encrypted_docs/`. |
| **A04:2021 – Insecure Design** | Ataques de enumeración de recursos o canal lateral por temporización (Timing Attacks). | - Si un documento o correo no coincide, se ejecuta trabajo computacional equivalente contra `DUMMY_PBKDF2_HASH`.<br>- Respuesta HTTP neutra uniforme (`HTTP 200` con mensaje genérico preventivo), impidiendo que un atacante deduzca la existencia de archivos o emails registrados. |
| **A05:2021 – Security Misconfiguration** | Cabeceras HTTP inseguras, modo Debug activo o permisos laxos. | - Configuración recomendada de cabeceras en settings (`SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS = 'DENY'`).<br>- La aplicación detiene el arranque en producción si `FREEDEC_FERNET_KEY` no está configurada o es inválida. |
| **A06:2021 – Vulnerable and Outdated Components** | Uso de dependencias obsoletas o con CVEs conocidos. | - Gestión de dependencias bloqueadas mediante **Poetry** (`pyproject.toml`).<br>- Dependencias modernas y mantenidas: `django = "^5.1"`, `djangorestframework = "^3.15"`, `cryptography = "^43.0"`. |
| **A07:2021 – Identification & Authentication Failures** | Ataques de fuerza bruta contra el código secreto de acceso. | - Rate limiting en el endpoint público mediante `AnonRateThrottle` en DRF.<br>- Requisito de alta entropía para códigos y longitud mínima de 8 caracteres para contraseñas. |
| **A08:2021 – Software & Data Integrity Failures** | Manipulación de archivos cifrados o datos no confiables. | - Integridad garantizada por Fernet: cualquier bit modificado en disco invalida el HMAC y rechaza el descifrado.<br>- Comprobación de integridad binaria SHA-256 en runtime.<br>- No se utiliza deserialización insegura (`pickle`, `yaml.load`). |
| **A09:2021 – Security Logging & Monitoring Failures** | Falta de visibilidad de ataques o filtración de credenciales en logs. | - **Auditoría Completa en Base de Datos**: Modelo `DocumentAccessLog` con registro inmutable de fecha, email solicitante, acción e IP remota.<br>- **Trazabilidad en Tiempo Real**: Métricas `access_count`, `last_accessed_at` y `last_accessed_by` en cada documento.<br>- **Regla de Cero Filtraciones**: **NUNCA** se registran contraseñas en texto plano ni códigos de acceso en los logs (solo hashes truncados). |
| **A10:2021 – Server-Side Request Forgery (SSRF)** | Peticiones HTTP arbitrarias iniciadas por el servidor. | - La aplicación no realiza peticiones HTTP salientes hacia URLs proporcionadas por usuarios. Todos los archivos se procesan directamente mediante streams locales `multipart/form-data`. |
| **Privacidad & GDPR / Derecho al Olvido** | Archivos confidenciales huérfanos tras eliminar registros. | - **Eliminación Física en Cascada**: Señal `post_delete` conectada a `EncryptedDocument` que borra físicamente el archivo `.enc` del disco en cualquier borrado de Django Admin, ORM o CLI (`delete_document`). |

---
---

<a id="section-english"></a>
# 🇬🇧 English

This document details the cryptographic design decisions, strict document format enforcement (PDF, LibreOffice, MS Office), and the **OWASP Top 10 Web Application Security Risks compliance matrix**.

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
| **A01:2021 – Broken Access Control** | Unauthorized uploads or unauthorized document key retrieval. | - Administration strictly centralized in Django Admin, protected by native Django staff/superuser authentication and model permissions.<br>- Total IDOR elimination: no sequential IDs; lookup is performed strictly by SHA-256 content hash.<br>- Django Admin panel configured with sensitive fields as `readonly_fields`. |
| **A02:2021 – Cryptographic Failures** | Weak keys, obsolete ciphers, or plaintext secret storage. | - Authenticated symmetric encryption (AEAD) with **AES-128-CBC + HMAC-SHA256 (Fernet)**.<br>- **Zero-Knowledge** storage of `access_code` hashed with **PBKDF2-SHA256**.<br>- Cryptographically secure PRNG (`secrets.token_urlsafe(32)` providing 256 bits of entropy).<br>- Mandatory startup key check in `apps.py`. |
| **A03:2021 – Injection** | SQL Injection, CRLF email header injection, or path traversal. | - **SQL Injection**: Parameterized queries via native Django ORM.<br>- **CRLF / Email Header Injection**: `validate_safe_email` rejects `\r`, `\n`, `%0a`, `%0d`, and catches `BadHeaderError`.<br>- **Anti-Path Traversal**: Original file name is strictly sanitized with `os.path.basename` and stored as `<original_filename>.enc`, completely preventing directory traversal attacks. |
| **A04:2021 – Insecure Design** | Document enumeration or side-channel Timing Attacks. | - Computes a simulated PBKDF2 hash against `DUMMY_PBKDF2_HASH` when a document is missing, matching latency.<br>- Uniform neutral response (`HTTP 200` with generic safe text) prevents probing resource existence. |
| **A05:2021 – Security Misconfiguration** | Insecure headers, active debug mode, or default keys. | - Recommended security headers configured (`SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS = 'DENY'`).<br>- Startup halts if `FREEDEC_FERNET_KEY` is missing or invalid in production. |
| **A06:2021 – Vulnerable and Outdated Components** | Obsolete dependencies with known CVEs. | - Locked dependencies managed via **Poetry** (`pyproject.toml`).<br>- Up-to-date and actively maintained dependencies: `django = "^5.1"`, `djangorestframework = "^3.15"`, `cryptography = "^43.0"`. |
| **A07:2021 – Identification & Authentication Failures** | Brute-force attacks against access codes. | - Perimeter rate limiting via `AnonRateThrottle` on the public endpoint.<br>- High entropy requirements for access codes and minimum 8-character password length. |
| **A08:2021 – Software & Data Integrity Failures** | Tampering with stored encrypted files or untrusted data. | - Fernet HMAC integrity: altering any bit on disk causes decryption failure.<br>- Runtime SHA-256 verification.<br>- No unsafe deserialization (`pickle`, `yaml.load`). |
| **A09:2021 – Security Logging & Monitoring Failures** | Lack of attack visibility or credential leakage in log files. | - **Comprehensive Database Audit Logging**: Inmutable `DocumentAccessLog` records timestamp, requester email, action, and remote IP.<br>- **Real-time Traceability**: `access_count`, `last_accessed_at`, and `last_accessed_by` tracked on every document.<br>- **Zero-Leakage Policy**: **NEVER** log plaintext passwords or access codes (only truncated hashes). |
| **A10:2021 – Server-Side Request Forgery (SSRF)** | Malicious outbound requests initiated by the server. | - The application never performs outbound requests to user-supplied URLs. All files are handled via local `multipart/form-data` streams. |
| **Privacy & GDPR / Right to Erasure** | Orphaned confidential encrypted files left on disk after database deletion. | - **Cascading Physical Erasure**: `post_delete` signal hooked to `EncryptedDocument` deletes physical `.enc` files from disk upon any deletion in Django Admin, ORM, or CLI (`delete_document`). |
