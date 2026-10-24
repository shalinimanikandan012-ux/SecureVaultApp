"""
SecureVaultApp - Vault Metadata, Encrypted Notes, and Encrypted Files Models
"""

from app import db
from datetime import datetime, timezone
import json

class VaultMetadata(db.Model):
    __tablename__ = 'vault_metadata'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True, index=True)
    salt = db.Column(db.String(64), nullable=False) # Base64 random salt for Argon2/PBKDF2
    iterations = db.Column(db.Integer, default=100000)
    algorithm = db.Column(db.String(32), default='AES-256-GCM')
    canary_ciphertext = db.Column(db.Text, nullable=False)
    canary_nonce = db.Column(db.String(32), nullable=False)
    canary_tag = db.Column(db.String(32), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class EncryptedNote(db.Model):
    __tablename__ = 'encrypted_notes'

    id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    title = db.Column(db.String(256), nullable=False)
    category = db.Column(db.String(64), default='Confidential')
    tags = db.Column(db.Text, default='[]')
    ciphertext = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.String(32), nullable=False)
    tag = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "tags": json.loads(self.tags) if self.tags else [],
            "encrypted_payload": {
                "ciphertext": self.ciphertext,
                "nonce": self.nonce,
                "tag": self.tag,
                "version": 1
            },
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

class EncryptedFile(db.Model):
    __tablename__ = 'encrypted_files'

    id = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = db.Column(db.String(256), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(128), default='application/octet-stream')
    sha256_checksum = db.Column(db.String(64), nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.String(32), nullable=False)
    tag = db.Column(db.String(32), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "size": self.size,
            "mime_type": self.mime_type,
            "sha256_checksum": self.sha256_checksum,
            "uploaded_at": self.uploaded_at.isoformat()
        }
