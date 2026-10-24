# SecureVaultApp Automated Testing & Execution Guide

## Windows PowerShell Setup & Test Execution

### Backend Pytest Execution
```powershell
# Open Windows PowerShell
cd SecureVaultApp\backend

# Create virtual environment if not present
python -m venv venv

# Activate execution policy & virtual environment
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run all unit and integration tests with coverage
pytest -v --tb=short
```

### Expected Pytest Output
```text
============================= test session starts ==============================
collected 9 items

tests/test_crypto.py::test_aes_gcm_encrypt_decrypt_valid PASSED          [ 11%]
tests/test_crypto.py::test_aes_gcm_tampered_ciphertext_fails PASSED      [ 22%]
tests/test_crypto.py::test_aes_gcm_tampered_tag_fails PASSED             [ 33%]
tests/test_crypto.py::test_aes_gcm_nonce_uniqueness PASSED               [ 44%]
tests/test_crypto.py::test_argon2id_password_hashing PASSED              [ 55%]
tests/test_auth.py::test_user_registration PASSED                        [ 66%]
tests/test_auth.py::test_user_registration_duplicate_fails PASSED        [ 77%]
tests/test_auth.py::test_login_invalid_credentials PASSED                [ 88%]
tests/test_auth.py::test_login_rate_limiting_lockout PASSED              [100%]

============================== 9 passed in 1.42s ===============================
```

---

## Frontend Vitest Execution
```powershell
cd SecureVaultApp\frontend
npm install
npm test
```
