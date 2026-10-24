"""
SecureVaultApp - User Database Model
"""

from app import db
from datetime import datetime, timezone
import json

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False, index=True)
    username = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(64), nullable=True) # Encrypted or stored safely
    recovery_code_hashes = db.Column(db.Text, default="[]") # JSON list of SHA-256 hashes
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    vault_metadata = db.relationship('VaultMetadata', backref='user', uselist=False, cascade="all, delete-orphan")
    notes = db.relationship('EncryptedNote', backref='user', lazy=True, cascade="all, delete-orphan")
    files = db.relationship('EncryptedFile', backref='user', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }

    def get_recovery_hashes(self):
        try:
            return json.loads(self.recovery_code_hashes)
        except Exception:
            return []

    def set_recovery_hashes(self, hashes_list):
        self.recovery_code_hashes = json.dumps(hashes_list)
