"""
Flask REST API - Vault Blueprint
Master Key Metadata & Canary Management
"""

from flask import Blueprint, request, jsonify, session
from app.models.vault import VaultMetadata
from app.models.user import User
from app.models.audit import AuditRecord
from app import db

vault_bp = Blueprint('vault', __name__, url_prefix='/api/vault')

@vault_bp.route('/metadata', methods=['GET'])
def get_metadata():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    meta = VaultMetadata.query.filter_by(user_id=user_id).first()
    if not meta:
        return jsonify({"configured": False}), 200
        
    return jsonify({
        "configured": True,
        "salt": meta.salt,
        "iterations": meta.iterations,
        "algorithm": meta.algorithm,
        "canary_ciphertext": meta.canary_ciphertext,
        "canary_nonce": meta.canary_nonce,
        "canary_tag": meta.canary_tag
    }), 200

@vault_bp.route('/initialize', methods=['POST'])
def initialize_vault():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.get_json() or {}
    salt = data.get('salt')
    iterations = data.get('iterations', 100000)
    canary_ct = data.get('canary_ciphertext')
    canary_nonce = data.get('canary_nonce')
    canary_tag = data.get('canary_tag')
    
    if not all([salt, canary_ct, canary_nonce, canary_tag]):
        return jsonify({"error": "Missing cryptographic parameters"}), 400
        
    user = User.query.get(user_id)
    meta = VaultMetadata.query.filter_by(user_id=user_id).first()
    if not meta:
        meta = VaultMetadata(user_id=user_id)
        db.session.add(meta)
        
    meta.salt = salt
    meta.iterations = iterations
    meta.canary_ciphertext = canary_ct
    meta.canary_nonce = canary_nonce
    meta.canary_tag = canary_tag
    db.session.commit()
    
    AuditRecord.append_event(
        actor_id=str(user_id),
        actor_email=user.email,
        action="VAULT_INITIALIZE",
        resource_type="VAULT",
        resource_id=str(user_id),
        status="SUCCESS",
        details="Vault master key derived and verification canary committed"
    )
    
    return jsonify({"message": "Vault initialized successfully"}), 200
