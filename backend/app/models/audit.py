"""
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
            "actor_id": str(actor_id),
            "action": action,
            "resource_type": resource_type,
            "resource_id": str(resource_id),
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
            actor_id=str(actor_id),
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            status=status,
            details=details,
            prev_hash=prev_hash
        )
        
        record = cls(
            block_index=index,
            timestamp=now_dt,
            actor_id=str(actor_id),
            actor_email=actor_email,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            status=status,
            details=details,
            prev_hash=prev_hash,
            block_hash=curr_hash
        )
        db.session.add(record)
        db.session.commit()
        return record

    def to_dict(self):
        return {
            "id": self.id,
            "index": self.block_index,
            "timestamp": self.timestamp.isoformat(),
            "actor_id": self.actor_id,
            "actor_email": self.actor_email,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "status": self.status,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "hash": self.block_hash
        }
