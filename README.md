# SecureVaultApp — Enterprise Cybersecurity & Cryptographic Vault

**Level 5 College Cybersecurity Capstone Project**  
*A complete, functional, zero-knowledge cryptographic web vault and digital forensics platform.*

---

## 1. Project Overview & Academic Goals

**SecureVaultApp** was engineered from the ground up to demonstrate mastery in modern application security, authenticated cryptography, and digital forensics. Unlike superficial prototypes that mock security controls or store plaintexts in browser storage, this project enforces:

1. **Zero-Knowledge Key Architecture**: Master passwords and derived 256-bit AES keys never touch non-volatile storage or server logs.
2. **Authenticated AEAD Encryption (AES-256-GCM)**: Guaranteed confidentiality and integrity with fresh 96-bit nonces and 128-bit authentication tags.
3. **Memory-Hard Authentication (Argon2id / PBKDF2-SHA256)**: Defense-in-depth against GPU/ASIC password cracking.
4. **RFC 6238 Multi-Factor Authentication (TOTP)**: 30-second time-step verification with emergency recovery codes.
5. **Tamper-Evident SHA-256 Digital Forensics Hash Chain**: Cryptographically linked audit logs with in-app integrity verification and report export.
6. **Educational Cryptography & Tamper Lab**: Live interactive testing harness demonstrating authentic cryptographic failures when bits are flipped or records manipulated.

---

## 2. Technology Stack

- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS v4, Lucide Icons, Motion.
- **Backend**: Python 3.11+, Flask REST API, Flask Blueprints, SQLAlchemy ORM.
- **Cryptographic Libraries**: `cryptography` (hazmat AESGCM), `argon2-cffi`, `pyotp`, Web Crypto API.
- **Database**: PostgreSQL (Production) / SQLite (Local development & Pytest).
- **Testing**: Pytest & Vitest for automated cryptographic and integration testing.

---

## 3. Directory Layout

```text
SecureVaultApp/
  frontend/                # React TypeScript Vite application
    src/
      components/          # Accessible UI components (Dashboard, Notes, Files, Lab)
      context/             # AuthContext & VaultContext (in-memory key lifecycle)
      services/            # crypto.ts, storage.ts, auditService.ts
      types/               # Domain interfaces & cryptographic types
  backend/                 # Python Flask application
    app/
      api/                 # REST Blueprints (auth, vault, notes, files, forensics)
      models/              # SQLAlchemy Models (user, vault_metadata, audit)
      security/            # crypto.py (Argon2id, AES-256-GCM)
    tests/                 # Pytest suites (test_crypto.py, test_auth.py)
    requirements.txt       # Dependencies
    wsgi.py                # WSGI entry point
  docs/                    # Architecture, security threat model, API, testing guides
```

---

## 4. Windows PowerShell Local Setup Instructions

### Backend (Python Flask)
```powershell
# Open Windows PowerShell
cd backend

# Create & activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Execute automated cryptographic and auth test suites
pytest -v

# Run backend development server (port 5000)
python wsgi.py
```

### Frontend (React Vite)
```powershell
# In a new PowerShell terminal
cd frontend
npm install
npm run dev
```

---

## 5. College Demonstration Workflow (12 Steps)

Reviewers and examiners can navigate to the built-in **Assessment Demo** tab to follow the 12 evaluation criteria:
1. **User Registration**: Register a new identity; verify unique salt generation.
2. **Brute-Force Throttling**: Test 5 failed attempts; observe progressive delay and 15-minute lockout.
3. **MFA Enrollment**: Scan/input Base32 secret; verify live RFC 6238 TOTP token and save recovery codes.
4. **Master Key Derivation**: Set a vault master password; verify canary verification payload.
5. **Encrypted Notes**: Create confidential note; use "Inspect Ciphertext" to confirm raw AEAD payload.
6. **File Vault**: Upload a confidential document; observe SHA-256 pre-calculation and AES-256-GCM encryption.
7. **Vault Lock**: Click "Lock Vault"; verify keys and plaintexts are instantly purged from memory.
8. **Integrity-Checked Decryption**: Unlock vault; download file and observe post-decryption SHA-256 checksum check.
9. **Security Monitoring**: Inspect activity log for authentication and vault operations.
10. **Forensic Hash Chain Verification**: Click "Recalculate Chain" to verify SHA-256 block linkages.
11. **Adversarial Tamper Lab**: Flip 1 bit in ciphertext or tag to witness authentic AEAD rejection.
12. **Forensic Report Export**: Export Markdown audit report; terminate session.

---

## 6. Academic License & Disclosures

Developed for Level 5 Higher Education Cybersecurity Assessment.  
Licensed under the Apache-2.0 License.
