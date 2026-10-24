"""
SecureVaultApp - Cryptographic Service
Real AES-256-GCM Authenticated Encryption & Argon2id Key Derivation
Compliant with NIST SP 800-38D and OWASP Password Storage Guidelines
"""

import os
import base64
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp

# NIST Recommended: 96-bit (12-byte) IV for AES-GCM to prevent GHASH reduction vulnerabilities
NONCE_LENGTH_BYTES = 12
KEY_LENGTH_BYTES = 32  # 256 bits

# Argon2id password hasher configuration (RFC 9106 recommended profiles)
ph = PasswordHasher(
    time_cost=3,          # 3 iterations
    memory_cost=65536,    # 64 MiB memory
    parallelism=4,        # 4 parallel lanes
    hash_len=32,          # 256-bit output key
    salt_len=16           # 128-bit random salt
)

def hash_login_password(password: str) -> str:
    """Hashes user login password with Argon2id and unique random salt."""
    return ph.hash(password)

def verify_login_password(password_hash: str, password: str) -> bool:
    """Constant-time verification of password against Argon2id hash."""
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False

def derive_vault_master_key(master_password: str, salt: bytes) -> bytes:
    """
    Derives 256-bit AES-GCM encryption key from Master Password using Argon2id.
    Zero-Knowledge: Master password and derived key are NEVER persisted.
    """
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        secret=master_password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=KEY_LENGTH_BYTES,
        type=Type.ID
    )

def encrypt_payload(data: bytes, key: bytes, associated_data: bytes = None) -> Dict[str, str]:
    """
    Encrypts plaintext with AES-256-GCM.
    Generates a cryptographically random 96-bit nonce for EVERY single operation.
    Returns: Base64-encoded ciphertext, nonce, and authentication tag.
    """
    if len(key) != KEY_LENGTH_BYTES:
        raise ValueError("Encryption key must be exactly 256 bits (32 bytes).")
    
    # 96-bit cryptographically secure random nonce
    nonce = os.urandom(NONCE_LENGTH_BYTES)
    aesgcm = AESGCM(key)
    
    # AESGCM.encrypt appends 16-byte tag to the ciphertext
    combined = aesgcm.encrypt(nonce, data, associated_data)
    
    ciphertext = combined[:-16]
    tag = combined[-16:]
    
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "version": 1
    }

def decrypt_payload(payload: Dict[str, str], key: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypts AES-256-GCM payload.
    Reconstitutes ciphertext + tag and verifies authentication tag.
    Fails safely with InvalidTag exception if ciphertext or tag was altered.
    """
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    tag = base64.b64decode(payload["tag"])
    
    combined = ciphertext + tag
    aesgcm = AESGCM(key)
    
    # Cryptographic tag verification occurs inside AESGCM.decrypt
    return aesgcm.decrypt(nonce, combined, associated_data)
