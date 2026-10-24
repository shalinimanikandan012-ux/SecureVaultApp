# SecureVaultApp Security Design, Threat Model & Invariants

## 1. Threat Model & Risk Analysis

### A. Assets Protected
- Master encryption keys and derived symmetric keys.
- User plaintext confidential notes and documents.
- User authentication credentials and MFA secrets.
- Digital forensic audit records and event history.

### B. Adversary Capabilities & Defenses

| Threat Scenario | Adversary Capability | Engineering Defense |
|---|---|---|
| Database Compromise | Adversary obtains complete SQL dump | All vault contents are stored as AES-256-GCM ciphertexts. Keys are derived on client only. |
| Nonce Reuse Attack | Adversary forces repeated IV under same key | 96-bit cryptographically secure pseudorandom generator (`os.urandom(12)`) enforces unique IV per operation. |
| Chosen-Ciphertext Attack (CCA) | Adversary alters bytes to infer plaintext | Authenticated Encryption with Associated Data (AEAD) with 128-bit authentication tag rejects altered ciphertexts before decryption. |
| Credential Stuffing & Brute Force | Automated credential dictionary scan | Argon2id memory-hard hashing ($m=64\text{MB}$), progressive response delay, and 15-minute lockout after 5 consecutive failures. |
| Inactivity Shoulder Surfing | Physical access to unattended terminal | Client auto-lock timer wipes in-memory master keys and clears DOM state upon inactivity. |
| Log Tampering | Rogue admin edits audit logs | SHA-256 hash chaining ($H_n = \text{SHA256}(H_{n-1} + \text{payload})$) detects any modification to past logs. |

---

## 2. Cryptographic Invariants & Standards Compliance

- **Symmetric Cipher**: AES-256 in Galois/Counter Mode (GCM) compliant with **NIST SP 800-38D**.
- **Nonce Length**: Exactly 96 bits (12 bytes) as recommended by NIST to avoid GHASH key derivation performance and collision issues.
- **Authentication Tag**: Exactly 128 bits (16 bytes) to maximize cryptographic forgery resistance ($2^{-128}$).
- **Password Hashing**: **Argon2id** (RFC 9106) with minimum 64 MiB memory, 3 iterations, and 4 lanes.
- **MFA Protocol**: **RFC 6238** (Time-Based One-Time Password Algorithm) with SHA-1/SHA-256, 30-second epoch intervals, and single-use emergency recovery codes hashed with SHA-256.

---

## 3. Disclosed Limitations (Level 5 Academic Integrity)

1. **Hash Chain vs. External Non-Repudiation**: A hash chain guarantees tamper-evidence inside the database. If an attacker with full database write access alters past blocks and recomputes all succeeding hashes, local verification will pass. For enterprise non-repudiation, the tip hash must be checkpointed to an external immutable ledger (e.g. signed transparency logs or public blockchain).
2. **Client-Side Memory Dump**: While master keys are never written to disk, an adversary with root/kernel access to the client device could inspect process RAM while the vault is actively unlocked. Auto-locking minimizes this window of exposure.
