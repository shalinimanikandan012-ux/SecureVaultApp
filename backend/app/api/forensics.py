"""
Flask REST API - Digital Forensics & Audit Blueprint
Hash chain verification, event filtering, and report export
"""

from flask import Blueprint, request, jsonify, session
from app.models.audit import AuditRecord, GENESIS_HASH
from app import db

forensics_bp = Blueprint('forensics', __name__, url_prefix='/api/forensics')

@forensics_bp.route('/events', methods=['GET'])
def list_events():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    records = AuditRecord.query.order_by(AuditRecord.block_index.asc()).all()
    return jsonify([r.to_dict() for r in records]), 200

@forensics_bp.route('/verify-chain', methods=['GET'])
def verify_chain():
    records = AuditRecord.query.order_by(AuditRecord.block_index.asc()).all()
    
    if not records:
        return jsonify({
            "is_valid": True,
            "total_checked": 0,
            "reason": "Audit log chain is empty."
        }), 200
        
    for i, record in enumerate(records):
        if record.block_index != i:
            return jsonify({
                "is_valid": False,
                "broken_at_index": i,
                "reason": f"Block index sequencing violation at position {i}"
            }), 200
            
        expected_prev = GENESIS_HASH if i == 0 else records[i - 1].block_hash
        if record.prev_hash != expected_prev:
            return jsonify({
                "is_valid": False,
                "broken_at_index": i,
                "reason": f"Severed hash chain linkage at block #{i}"
            }), 200
            
        calculated_hash = AuditRecord.compute_canonical_hash(
            index=record.block_index,
            timestamp_iso=record.timestamp.isoformat(),
            actor_id=record.actor_id,
            action=record.action,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            status=record.status,
            details=record.details,
            prev_hash=record.prev_hash
        )
        if calculated_hash != record.block_hash:
            return jsonify({
                "is_valid": False,
                "broken_at_index": i,
                "reason": f"Payload modification detected in block #{i}"
            }), 200
            
    return jsonify({
        "is_valid": True,
        "total_checked": len(records),
        "reason": f"All {len(records)} audit chain blocks cryptographically verified"
    }), 200
