# SecureVaultApp System Architecture

## 1. High-Level Monorepo Structure

```text
SecureVaultApp/
  frontend/
    src/
      components/          # Accessible UI components (Header, Sidebar, Modals)
      context/             # AuthContext (sessions) & VaultContext (in-memory keys)
      services/            # crypto.ts (AES-GCM, PBKDF2, TOTP), storage.ts, auditService.ts
      types/               # Fully typed TypeScript domain definitions
    index.html
    package.json
    vite.config.ts
  backend/
    app/
      api/                 # REST blueprints: auth, vault, notes, files, forensics
      models/              # SQLAlchemy models: user, vault_metadata, encrypted_note, audit
      security/            # crypto.py (Argon2id, AES-GCM via cryptography library)
    tests/                 # Pytest test suites (test_crypto.py, test_auth.py)
    requirements.txt       # Production dependencies
    wsgi.py                # WSGI entry point
  docs/
    architecture.md        # System architecture and data flow diagrams
    security.md            # Threat model, CIA triad, and cryptographic invariants
    api.md                 # Complete REST API specification
    deployment.md          # Production deployment guide (Render, Vercel, Supabase)
    testing.md             # PowerShell and Bash automated testing procedures
  README.md                # Comprehensive Level 5 College Project submission guide
  .gitignore
```

## 2. Cryptographic Data Flow

### A. Authentication & Session Initialization
1. User supplies `(email, password)`.
2. Password is verified against `Argon2id` hash with random salt ($m=64\text{MB}, t=3, p=4$).
3. If MFA is configured, an RFC 6238 TOTP token is verified with dynamic truncation and $\pm 1$ step drift allowance.
4. Session token is generated and returned to client.

### B. Zero-Knowledge Vault Unlocking
1. User provides `master_password` (distinct from login credentials).
2. Client derives 256-bit AES-GCM key using `Argon2id` / `PBKDF2-SHA256` (100,000 iterations).
3. Derived candidate key attempts decryption of stored `canary_ciphertext`.
4. If GCM authentication tag matches, candidate key is stored **in volatile memory only**.
5. Inactivity auto-lock listener monitors mouse/keyboard events; upon timeout, key is set to `null` and decrypted data is cleared.

### C. Note & File Encryption Flow
1. Plaintext buffer generated in client memory.
2. Cryptographically secure 96-bit (12-byte) nonce generated: `os.urandom(12)` / `crypto.getRandomValues`.
3. Plaintext encrypted with `AES-256-GCM` with AAD bound to the record identifier.
4. Output split into Base64 `nonce`, `ciphertext`, and 128-bit `tag`.
5. Nonce and tag are stored alongside ciphertext. Plaintext is discarded immediately.
