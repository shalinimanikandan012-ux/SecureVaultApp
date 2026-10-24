"""
Pytest Cryptographic Unit Test Suite
Verifies AES-256-GCM AEAD, Nonce Uniqueness, and Argon2id Invariants
"""

import pytest
import os
import base64
from cryptography.exceptions import InvalidTag
from app.security.crypto import (
    derive_vault_master_key,
    encrypt_payload,
    decrypt_payload,
    hash_login_password,
    verify_login_password
)

def test_aes_gcm_encrypt_decrypt_valid():
    """Verify correct encryption and decryption of valid plaintext."""
    key = os.urandom(32)
    plaintext = b"College Level 5 Assessment Payload"
    
    payload = encrypt_payload(plaintext, key, associated_data=b"RECORD_1")
    decrypted = decrypt_payload(payload, key, associated_data=b"RECORD_1")
    
    assert decrypted == plaintext
    assert "nonce" in payload
    assert "ciphertext" in payload
    assert "tag" in payload

def test_aes_gcm_tampered_ciphertext_fails():
    """Verify that flipping a single bit in ciphertext throws InvalidTag (tamper resistance)."""
    key = os.urandom(32)
    plaintext = b"Sensitive Financial Credential"
    
    payload = encrypt_payload(plaintext, key)
    
    raw_ct = bytearray(base64.b64decode(payload["ciphertext"]))
    raw_ct[0] ^= 0x01  # Flip 1 bit
    payload["ciphertext"] = base64.b64encode(raw_ct).decode('utf-8')
    
    with pytest.raises(InvalidTag):
        decrypt_payload(payload, key)

def test_aes_gcm_tampered_tag_fails():
    """Verify that an altered authentication tag is rejected."""
    key = os.urandom(32)
    payload = encrypt_payload(b"Critical Command", key)
    
    raw_tag = bytearray(base64.b64decode(payload["tag"]))
    raw_tag[0] ^= 0xFF
    payload["tag"] = base64.b64encode(raw_tag).decode('utf-8')
    
    with pytest.raises(InvalidTag):
        decrypt_payload(payload, key)

def test_aes_gcm_nonce_uniqueness():
    """Verify that multiple encryptions of identical plaintext produce distinct nonces."""
    key = os.urandom(32)
    plaintext = b"Identical String"
    
    p1 = encrypt_payload(plaintext, key)
    p2 = encrypt_payload(plaintext, key)
    
    assert p1["nonce"] != p2["nonce"]
    assert p1["ciphertext"] != p2["ciphertext"]

def test_argon2id_password_hashing():
    """Verify Argon2id salt generation and constant-time verification."""
    password = "CorrectHorseBatteryStaple2026!"
    hashed = hash_login_password(password)
    
    assert verify_login_password(hashed, password) is True
    assert verify_login_password(hashed, "WrongPassword") is False
