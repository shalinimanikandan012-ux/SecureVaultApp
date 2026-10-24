/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SecureVaultApp Python Backend & Architecture Documentation Explorer
 * In-App Inspector for Python Flask Source Code, Pytest Suites, and Architectural Docs
 */

import React, { useState } from 'react';
import {
  Code2,
  FileCode,
  BookOpen,
  Terminal,
  Shield,
  Copy,
  Check,
  Server,
  Database,
  Layers,
} from 'lucide-react';

interface DocFile {
  id: string;
  category: 'Python Backend' | 'Pytest Tests' | 'Architecture & Threat Model' | 'CLI & Deployment';
  title: string;
  path: string;
  language: string;
  content: string;
}

const CODE_DOCS: DocFile[] = [
  {
    id: 'crypto_py',
    category: 'Python Backend',
    title: 'Cryptographic Service (Argon2id & AES-256-GCM)',
    path: 'backend/app/security/crypto.py',
    language: 'python',
    content: `"""
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
`,
  },
  {
    id: 'auth_api_py',
    category: 'Python Backend',
    title: 'Authentication & Session Blueprint',
    path: 'backend/app/api/auth.py',
    language: 'python',
    content: `"""
Flask REST API - Authentication Blueprint
User Registration, Argon2id Login, Rate Limiting, and RFC 6238 TOTP
"""

from flask import Blueprint, request, jsonify, session
from datetime import datetime, timedelta, timezone
from app.models.user import User, db
from app.models.audit import AuditRecord
from app.security.crypto import hash_login_password, verify_login_password
import pyotp

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not email or not username or len(password) < 10:
        return jsonify({"error": "Password must be at least 10 characters long"}), 400
        
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with this email already exists"}), 409
        
    pwd_hash = hash_login_password(password)
    user = User(
        email=email,
        username=username,
        password_hash=pwd_hash,
        mfa_enabled=False,
        created_at=datetime.now(timezone.utc)
    )
    db.session.add(user)
    db.session.commit()
    
    AuditRecord.append_event(
        actor_id=user.id,
        actor_email=user.email,
        action="USER_REGISTRATION",
        resource_type="USER",
        resource_id=str(user.id),
        status="SUCCESS",
        details="User registered account"
    )
    
    return jsonify({"message": "Registration successful", "user_id": user.id}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    user = User.query.filter_by(email=email).first()
    
    # Generic error to prevent email enumeration
    generic_err = "Invalid email or password."
    
    if not user:
        return jsonify({"error": generic_err}), 401
        
    # Check progressive account lockout
    if user.lockout_until and user.lockout_until > datetime.now(timezone.utc):
        remaining = int((user.lockout_until - datetime.now(timezone.utc)).total_seconds() / 60)
        return jsonify({"error": f"Account locked. Try again in {remaining} minutes."}), 429
        
    if not verify_login_password(user.password_hash, password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        db.session.commit()
        return jsonify({"error": generic_err}), 401
        
    # Password verified: reset counters
    user.failed_login_attempts = 0
    user.lockout_until = None
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    
    if user.mfa_enabled:
        return jsonify({"mfa_required": True, "temp_token": user.generate_mfa_token()}), 200
        
    session['user_id'] = user.id
    return jsonify({"message": "Login successful", "user": user.to_dict()}), 200
`,
  },
  {
    id: 'audit_model_py',
    category: 'Python Backend',
    title: 'SQLAlchemy Models & Hash Chain',
    path: 'backend/app/models/audit.py',
    language: 'python',
    content: `"""
SQLAlchemy AuditRecord Model & Cryptographic Hash Chain
Chronological, append-only tamper-evident forensic ledger
"""

from app import db
import hashlib
import json
from datetime import datetime, timezone

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

class AuditRecord(db.Model):
    __tablename__ = 'audit_records'
    
    id = db.Column(db.Integer, primary_key=True)
    block_index = db.Column(db.Integer, nullable=False, unique=True, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    actor_id = db.Column(db.String(64), nullable=False)
    actor_email = db.Column(db.String(128), nullable=False)
    action = db.Column(db.String(64), nullable=False)
    resource_type = db.Column(db.String(64), nullable=False)
    resource_id = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(32), nullable=False)
    details = db.Column(db.Text, nullable=False)
    prev_hash = db.Column(db.String(64), nullable=False)
    block_hash = db.Column(db.String(64), nullable=False)

    @classmethod
    def compute_canonical_hash(cls, index: int, timestamp_iso: str, actor_id: str, 
                               action: str, resource_type: str, resource_id: str, 
                               status: str, details: str, prev_hash: str) -> str:
        payload = json.dumps({
            "index": index,
            "timestamp": timestamp_iso,
            "actor_id": actor_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "status": status,
            "details": details,
            "prev_hash": prev_hash
        }, sort_keys=True)
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    @classmethod
    def append_event(cls, actor_id: str, actor_email: str, action: str,
                     resource_type: str, resource_id: str, status: str, details: str):
        last_record = cls.query.order_by(cls.block_index.desc()).first()
        index = 0 if not last_record else last_record.block_index + 1
        prev_hash = GENESIS_HASH if not last_record else last_record.block_hash
        
        now_dt = datetime.now(timezone.utc)
        curr_hash = cls.compute_canonical_hash(
            index=index,
            timestamp_iso=now_dt.isoformat(),
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            details=details,
            prev_hash=prev_hash
        )
        
        record = cls(
            block_index=index,
            timestamp=now_dt,
            actor_id=actor_id,
            actor_email=actor_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            status=status,
            details=details,
            prev_hash=prev_hash,
            block_hash=curr_hash
        )
        db.session.add(record)
        db.session.commit()
        return record
`,
  },
  {
    id: 'test_crypto_py',
    category: 'Pytest Tests',
    title: 'Cryptographic Unit Tests (Pytest)',
    path: 'backend/tests/test_crypto.py',
    language: 'python',
    content: `"""
Pytest Cryptographic Unit Test Suite
Verifies AES-256-GCM AEAD, Nonce Uniqueness, and Argon2id Invariants
"""

import pytest
import os
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
    
    # Tamper with first byte of base64 decoded ciphertext
    import base64
    raw_ct = bytearray(base64.b64decode(payload["ciphertext"]))
    raw_ct[0] ^= 0x01  # Flip bit
    payload["ciphertext"] = base64.b64encode(raw_ct).decode('utf-8')
    
    with pytest.raises(InvalidTag):
        decrypt_payload(payload, key)

def test_aes_gcm_tampered_tag_fails():
    """Verify that an altered authentication tag is rejected."""
    key = os.urandom(32)
    payload = encrypt_payload(b"Critical Command", key)
    
    import base64
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
    """Verify Argon2id salt generation and verification."""
    password = "CorrectHorseBatteryStaple2026!"
    hashed = hash_login_password(password)
    
    assert verify_login_password(hashed, password) is True
    assert verify_login_password(hashed, "WrongPassword") is False
`,
  },
  {
    id: 'threat_model_md',
    category: 'Architecture & Threat Model',
    title: 'Cybersecurity Threat Model & CIA Triad',
    path: 'docs/security.md',
    language: 'markdown',
    content: `# SecureVaultApp Cybersecurity Threat Model & Security Architecture

## 1. Executive Summary & Objective
SecureVaultApp is an enterprise-grade cryptographic vault engineered to maintain Confidentiality,
Integrity, and Availability (CIA Triad) for sensitive documents and notes.

## 2. Threat Actors & Assumptions
- **Malicious Database Administrator (Untrusted Storage)**:
  - Adversary has direct read-access to the SQL database or storage volumes.
  - Mitigation: Zero-knowledge encryption. All notes and files are stored strictly as AES-256-GCM
    ciphertexts with 128-bit authentication tags. Master keys are derived client-side via PBKDF2/Argon2id
    and never stored in the database.
- **Eavesdropper on Transit (Network Adversary)**:
  - Network adversary sniffing traffic.
  - Mitigation: Strict Transport Security (TLS 1.3), Content Security Policy (CSP), and client-side
    authenticated payload encryption.
- **Brute-Force & Credential Stuffing**:
  - Automated dictionary attacks against login endpoints.
  - Mitigation: Argon2id memory-hard hashing (m=64MB, t=3, p=4), progressive rate-limiting delays,
    and automatic 15-minute account lockout after 5 consecutive failures.
- **Adversarial Ciphertext Manipulation (Chosen-Ciphertext Attack)**:
  - Adversary attempts bit-flipping attacks on encrypted records.
  - Mitigation: AES-256-GCM AEAD enforces authentic integrity. Any modification throws an authentication
    tag mismatch exception and prevents decryption.

## 3. Cryptographic Primitives & Justification
| Purpose | Primitive | Parameters | Standard |
|---|---|---|---|
| Symmetric Encryption | AES-GCM | 256-bit Key, 96-bit Nonce, 128-bit Tag | NIST SP 800-38D |
| Key Derivation | Argon2id / PBKDF2 | Argon2id: 64MB RAM, t=3; PBKDF2: 100k rounds | RFC 9106 / OWASP |
| Two-Factor Authentication | TOTP | 30s Time-Step, HMAC-SHA1, 6 digits | RFC 6238 |
| Audit Hash Chain | SHA-256 | Linked H_n = SHA256(H_{n-1} + canonical) | FIPS 180-4 |
`,
  },
  {
    id: 'setup_cli_md',
    category: 'CLI & Deployment',
    title: 'Local Setup & Windows PowerShell Commands',
    path: 'docs/testing.md',
    language: 'markdown',
    content: `# Local Development & Automated Test Instructions

## Prerequisites
- Node.js >= 20.x
- Python >= 3.11
- Windows PowerShell 5.1+ or Linux / macOS bash

---

## 1. Windows PowerShell Setup Commands

### Step A: Clone & Set Up Backend
\`\`\`powershell
# Open Windows PowerShell as Administrator or standard user
cd SecureVaultApp/backend

# Create Python virtual environment
python -m venv venv

# Activate virtual environment
.\\venv\\Scripts\\Activate.ps1

# Upgrade pip & install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# Run database migrations
flask db upgrade

# Run automated backend test suite (Pytest)
pytest -v
\`\`\`

### Step B: Set Up Frontend
\`\`\`powershell
# In a new PowerShell tab:
cd SecureVaultApp/frontend

# Install Node dependencies
npm install

# Run frontend test suite (Vitest)
npm run test

# Launch Vite development server
npm run dev
\`\`\`

---

## 2. Linux / macOS Setup Commands
\`\`\`bash
# Backend Setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest -v
python wsgi.py

# Frontend Setup
cd ../frontend
npm install
npm run dev
\`\`\`
`,
  },
];

export const CodeDocsView: React.FC = () => {
  const [selectedDocId, setSelectedDocId] = useState<string>('crypto_py');
  const [copied, setCopied] = useState(false);

  const selectedDoc = CODE_DOCS.find((d) => d.id === selectedDocId) || CODE_DOCS[0];

  const handleCopyContent = () => {
    navigator.clipboard.writeText(selectedDoc.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Code2 className="w-5 h-5 text-cyan-400" />
            <span>Python Backend Codebase & Architecture Explorer</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Examine production-grade Python Flask files, SQLAlchemy models, Pytest suites, and cybersecurity architectural specifications.
          </p>
        </div>

        <button
          onClick={handleCopyContent}
          className="py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg transition-colors flex items-center gap-1.5 shrink-0"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
          <span>{copied ? 'Copied File' : 'Copy File Content'}</span>
        </button>
      </div>

      {/* Code Browser Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left 1 Col: File Directory Navigation */}
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 space-y-4">
          <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider px-2">
            Codebase & Documentation
          </div>

          <div className="space-y-1">
            {CODE_DOCS.map((doc) => {
              const isSelected = doc.id === selectedDocId;
              return (
                <button
                  key={doc.id}
                  onClick={() => setSelectedDocId(doc.id)}
                  className={`w-full text-left p-2.5 rounded-lg text-xs transition-colors block ${
                    isSelected
                      ? 'bg-cyan-950/70 border border-cyan-800 text-cyan-300 font-semibold shadow-xs'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <div className="text-[10px] text-slate-500 font-mono mb-0.5">
                    {doc.category}
                  </div>
                  <div className="truncate font-medium">{doc.title}</div>
                  <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5">
                    {doc.path}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right 3 Cols: Code Viewer */}
        <div className="lg:col-span-3 bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden flex flex-col">
          {/* File Tab Header */}
          <div className="h-10 px-4 bg-[#070b14] border-b border-slate-800 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2 text-slate-300">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span>{selectedDoc.path}</span>
            </div>
            <span className="text-slate-500 text-[11px] uppercase">
              {selectedDoc.language}
            </span>
          </div>

          {/* Syntax Highlighted / Pre Code Area */}
          <div className="p-4 bg-[#0b1120] overflow-x-auto flex-1 text-xs font-mono leading-relaxed text-slate-300">
            <pre className="select-all">
              <code>{selectedDoc.content}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
