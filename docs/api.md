# SecureVaultApp REST API Specification

Base URL: `/api`

All JSON requests must supply `Content-Type: application/json`.
All protected routes require an active session cookie or Bearer token header.

---

## 1. Authentication Endpoints (`/api/auth`)

### `POST /api/auth/register`
Creates a new user identity with Argon2id password hash.
- **Request Body**:
  ```json
  {
    "email": "user@securevault.internal",
    "username": "Analyst Alice",
    "password": "CorrectHorseBatteryStaple2026!"
  }
  ```
- **Response (201 Created)**:
  ```json
  {
    "message": "Registration successful",
    "user": {
      "id": 1,
      "email": "user@securevault.internal",
      "username": "Analyst Alice",
      "mfa_enabled": false
    }
  }
  ```

### `POST /api/auth/login`
Authenticates user, checks progressive lockout, and handles MFA requirement.
- **Request Body**:
  ```json
  {
    "email": "user@securevault.internal",
    "password": "CorrectHorseBatteryStaple2026!"
  }
  ```
- **Response (200 OK - No MFA)**:
  ```json
  {
    "message": "Login successful",
    "user": { "id": 1, "email": "user@securevault.internal", "mfa_enabled": false }
  }
  ```
- **Response (200 OK - MFA Required)**:
  ```json
  {
    "mfa_required": true,
    "temp_token": "mfa_1_1742080000"
  }
  ```
- **Response (429 Too Many Requests - Locked)**:
  ```json
  {
    "error": "Account temporarily locked. Try again in 14 minutes."
  }
  ```

### `POST /api/auth/mfa/verify`
Validates 6-digit TOTP token or single-use recovery code.
- **Request Body**:
  ```json
  {
    "user_id": 1,
    "code": "482910"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "message": "MFA verified",
    "user": { "id": 1, "email": "user@securevault.internal" }
  }
  ```

---

## 2. Vault Endpoints (`/api/vault`)

### `GET /api/vault/metadata`
Returns non-secret key derivation parameters and verification canary.
- **Response (200 OK)**:
  ```json
  {
    "configured": true,
    "salt": "base64-random-salt",
    "iterations": 100000,
    "algorithm": "AES-256-GCM",
    "canary_ciphertext": "base64-canary",
    "canary_nonce": "base64-nonce",
    "canary_tag": "base64-tag"
  }
  ```

### `POST /api/vault/initialize`
Commits salt and canary payload upon master key configuration.

---

## 3. Notes Endpoints (`/api/notes`)

- `GET /api/notes` - Returns list of encrypted notes for authenticated user.
- `POST /api/notes` - Commits AES-256-GCM ciphertext payload and metadata.
- `DELETE /api/notes/<id>` - Purges note ciphertext from database.

---

## 4. Digital Forensics Endpoints (`/api/forensics`)

- `GET /api/forensics/events` - Retrieves chronological audit log records.
- `GET /api/forensics/verify-chain` - Recalculates all SHA-256 block hashes and validates integrity linkage.
