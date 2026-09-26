# Arquitectura del Sistema Freedec / Freedec System Architecture

<p align="center">
  <a href="#seccion-espanol"><b>🇪🇸 Leer en Español</b></a> &nbsp;&nbsp;|&nbsp;&nbsp; 
  <a href="#section-english"><b>🇬🇧 Read in English</b></a>
</p>

---

<a id="seccion-espanol"></a>
# 🇪🇸 Español

Este documento describe la arquitectura interna, el flujo de datos criptográficos y los diagramas de secuencia y flujo para la aplicación **Freedec**.

---

## 1. Visión General de la Arquitectura

Freedec implementa un patrón de **arquitectura orientada a servicios desacoplados** dentro del ecosistema Django / Django REST Framework (DRF):

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Capa de Entrada (DRF Views / Web GUI)           │
│   - AdminDocumentUploadView / AdminUploadGuiView (Auth Requerida)      │
│   - PublicPasswordRequestView / PublicRequestGuiView (Acceso Público)  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Capa de Validación (Forms & Serializers)           │
│   - AdminDocumentUploadSerializer / AdminDocumentUploadForm            │
│   - PublicPasswordRequestSerializer / PublicPasswordRequestForm        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Capa de Negocio (Services)                         │
│   - DocumentManagementService: Orquesta flujos de negocio              │
│   - FernetCryptoService: Motor simétrico autenticado (AES-128-CBC+HMAC)│
│   - calculate_file_sha256(): Motor streaming de hash en chunks (64KB)  │
│   - validators.py: Inspección de Magic Bytes y Anti-Zip Bomb           │
└───────────────────────┬───────────────────────────────┬────────────────┘
                        │                               │
                        ▼                               ▼
┌────────────────────────────────┐            ┌──────────────────────────┐
│      Capa de Persistencia      │            │     Servicio Externo     │
│   - EncryptedDocument (BD)     │            │   - django.core.mail     │
│   - Disco (encrypted_docs/)    │            │     (Console / SMTP)     │
└────────────────────────────────┘            └──────────────────────────┘
```

---

## 2. Diagramas de Flujo

### 2.1. Subida y Cifrado (Administrador)

```mermaid
flowchart TD
    A(["Inicio: Petición Admin GUI / API"]) --> B{"¿Usuario Autenticado?"}
    B -- "No" --> C["Redirigir a Login o HTTP 401"]
    B -- "Sí" --> D["Validar Formulario / Serializador"]
    D --> E{"¿Formato y Magic Bytes Válidos?"}
    E -- "No" --> F["Retornar Error de Formato No Permitido"]
    E -- "Sí" --> G["calculate_file_sha256: Streaming 64 KB"]
    G --> H{"¿Ya existe file_hash en BD?"}
    H -- "Sí" --> I["Retornar Error: Documento duplicado"]
    H -- "No" --> J["FernetCryptoService: Cifrar archivo con AES-128-CBC + HMAC"]
    J --> K["Guardar archivo cifrado en disco 'encrypted_docs/'"]
    K --> L["secrets.token_urlsafe: Generar access_code 256 bits"]
    L --> M["make_password: Generar hash PBKDF2 del access_code"]
    M --> N["FernetCryptoService: Cifrar contraseña con Fernet"]
    N --> O["Normalizar emails a minúsculas anti-CRLF"]
    O --> P["Guardar EncryptedDocument en Base de Datos"]
    P --> Q(["Retornar Éxito con file_hash, access_code y URL de descarga"])
```

---

### 2.2. Verificación y Recuperación (Público)

```mermaid
flowchart TD
    A(["Inicio: Petición Pública GUI / API"]) --> B["Rate Limiting: Verificar Throttling"]
    B -- "Límite Excedido" --> C["Retornar HTTP 429 Too Many Requests"]
    B -- "OK" --> D["Validar Formulario / Serializador"]
    D --> E{"¿Formato Válido?"}
    E -- "No" --> F["Retornar Error"]
    E -- "Sí" --> G["calculate_file_sha256: Calcular hash en memoria"]
    G --> H{"¿Existe file_hash en BD?"}
    
    H -- "No" --> I["Simular verificación con DUMMY_HASH para mitigar Timing Attack"]
    I --> J["Registrar advertencia de seguridad en log"]
    J --> K(["Retornar Mensaje Neutro de Seguridad"])
    
    H -- "Sí" --> L{"¿Coincide access_code vía check_password?"}
    L -- "No" --> J
    L -- "Sí" --> M{"¿Email solicitante está en allowed_emails?"}
    M -- "No" --> J
    M -- "Sí" --> N["FernetCryptoService: Descifrar contraseña interna"]
    N --> O["django.core.mail: Enviar contraseña por correo"]
    O --> P["Registrar auditoría de despacho exitoso"]
    P --> K
```

---

## 3. Modelo de Datos (`EncryptedDocument`)

| Campo | Tipo | Restricciones | Propósito de Seguridad |
| :--- | :--- | :--- | :--- |
| `file_hash` | `CharField(64)` | `unique=True`, `db_index=True` | Identificador criptográfico SHA-256 del archivo original. |
| `encrypted_file` | `FileField` | `upload_to='encrypted_docs/'` | Contenido binario cifrado en reposo con AES/Fernet. |
| `access_code` | `CharField(128)` | Hash PBKDF2 | Almacenamiento Zero-Knowledge del código secreto. |
| `encrypted_password`| `TextField` | Token base64 Fernet | Clave o contraseña cifrada con la clave maestra `FREEDEC_FERNET_KEY`. |
| `allowed_emails` | `JSONField` | `default=list` | Lista blanca de correos normalizados en minúsculas. |
| `created_at` | `DateTimeField`| `auto_now_add=True` | Trazabilidad y auditoría temporal. |
| `updated_at` | `DateTimeField`| `auto_now=True` | Trazabilidad de modificaciones. |

---
---

<a id="section-english"></a>
# 🇬🇧 English

This document outlines the internal architecture, cryptographic data flow, and flowcharts for the **Freedec** application.

---

## 1. Architectural Overview

Freedec implements a **decoupled service-oriented pattern** inside the Django / Django REST Framework (DRF) ecosystem:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Ingress Layer (DRF Views / Web GUI)             │
│   - AdminDocumentUploadView / AdminUploadGuiView (Auth Required)       │
│   - PublicPasswordRequestView / PublicRequestGuiView (Public Access)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Validation Layer (Forms & Serializers)             │
│   - AdminDocumentUploadSerializer / AdminDocumentUploadForm            │
│   - PublicPasswordRequestSerializer / PublicPasswordRequestForm        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       Service Layer (Services)                         │
│   - DocumentManagementService: Business workflow orchestrator          │
│   - FernetCryptoService: Authenticated symmetric cipher (AES-128-CBC)  │
│   - calculate_file_sha256(): Memory-safe chunked hashing (64 KB)       │
│   - validators.py: Deep Magic Byte inspection & Anti-Zip Bomb          │
└───────────────────────┬───────────────────────────────┬────────────────┘
                        │                               │
                        ▼                               ▼
┌────────────────────────────────┐            ┌──────────────────────────┐
│       Persistence Layer        │            │     External Service     │
│   - EncryptedDocument (DB)     │            │   - django.core.mail     │
│   - Disk (encrypted_docs/)     │            │     (Console / SMTP)     │
└────────────────────────────────┘            └──────────────────────────┘
```

---

## 2. Flowcharts

### 2.1. Admin Upload and Encryption Flow

```mermaid
flowchart TD
    A(["Start: Admin GUI / API Request"]) --> B{"Authenticated User?"}
    B -- "No" --> C["Redirect to Login or HTTP 401"]
    B -- "Yes" --> D["Validate Form / Serializer"]
    D --> E{"Valid Format & Magic Bytes?"}
    E -- "No" --> F["Return Format Rejection Error"]
    E -- "Yes" --> G["calculate_file_sha256: 64 KB Chunked Streaming"]
    G --> H{"Does file_hash exist in DB?"}
    H -- "Yes" --> I["Return Error: Duplicate document"]
    H -- "No" --> J["FernetCryptoService: Encrypt file with AES-128-CBC + HMAC"]
    J --> K["Save encrypted file to disk 'encrypted_docs/'"]
    K --> L["secrets.token_urlsafe: Generate 256-bit access_code"]
    L --> M["make_password: Generate PBKDF2 hash of access_code"]
    M --> N["FernetCryptoService: Encrypt password with Fernet"]
    N --> O["Normalize emails to lowercase anti-CRLF"]
    O --> P["Persist EncryptedDocument to Database"]
    P --> Q(["Return Success with file_hash, access_code, and download URL"])
```

---

### 2.2. Public Verification and Password Retrieval Flow

```mermaid
flowchart TD
    A(["Start: Public GUI / API Request"]) --> B["Rate Limiting: Check Throttling"]
    B -- "Exceeded" --> C["Return HTTP 429 Too Many Requests"]
    B -- "OK" --> D["Validate Form / Serializer"]
    D --> E{"Valid Format?"}
    E -- "No" --> F["Return Error"]
    E -- "Yes" --> G["calculate_file_sha256: Compute runtime SHA-256"]
    G --> H{"Does file_hash exist in DB?"}
    
    H -- "No" --> I["Simulate verification with DUMMY_HASH to mitigate Timing Attacks"]
    I --> J["Log security audit warning"]
    J --> K(["Return Neutral Safety Message"])
    
    H -- "Yes" --> L{"Does access_code match via check_password?"}
    L -- "No" --> J
    L -- "Yes" --> M{"Is requester email in allowed_emails?"}
    M -- "No" --> J
    M -- "Yes" --> N["FernetCryptoService: Decrypt internal password"]
    N --> O["django.core.mail: Send password to verified email"]
    O --> P["Log successful dispatch audit"]
    P --> K
```

---

## 3. Data Model (`EncryptedDocument`)

| Field | Type | Constraints | Security Purpose |
| :--- | :--- | :--- | :--- |
| `file_hash` | `CharField(64)` | `unique=True`, `db_index=True` | Cryptographic SHA-256 identifier of original unencrypted file. |
| `encrypted_file` | `FileField` | `upload_to='encrypted_docs/'` | Binary content encrypted at rest with AES/Fernet. |
| `access_code` | `CharField(128)` | PBKDF2 Hash | Zero-Knowledge storage of secret access code. |
| `encrypted_password`| `TextField` | Fernet base64 token | Decryption key encrypted with `FREEDEC_FERNET_KEY`. |
| `allowed_emails` | `JSONField` | `default=list` | Whitelist of normalized lowercase email addresses. |
| `created_at` | `DateTimeField`| `auto_now_add=True` | Audit trail and temporal traceability. |
| `updated_at` | `DateTimeField`| `auto_now=True` | Traceability of modifications. |
