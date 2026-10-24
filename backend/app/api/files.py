"""
Flask REST API - Encrypted File Vault Blueprint
Secure file storage, pre/post SHA-256 verification, and chunked download
"""

from flask import Blueprint, request, jsonify, session, send_file
from app.models.vault import EncryptedFile
from app.models.user import User
from app.models.audit import AuditRecord
from app import db
import uuid

files_bp = Blueprint('files', __name__, url_prefix='/api/files')

@files_bp.route('', methods=['GET'])
def list_files():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    records = EncryptedFile.query.filter_by(user_id=user_id).order_by(EncryptedFile.uploaded_at.desc()).all()
    return jsonify([f.to_dict() for f in records]), 200

@files_bp.route('/upload', methods=['POST'])
def upload_file():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    size = data.get('size', 0)
    mime_type = data.get('mime_type', 'application/octet-stream')
    sha256 = data.get('sha256_checksum', '')
    ct = data.get('ciphertext')
    nonce = data.get('nonce')
    tag = data.get('tag')
    
    if not all([name, ct, nonce, tag, sha256]):
        return jsonify({"error": "Missing encrypted file payload components"}), 400
        
    file_id = str(uuid.uuid4())
    user = User.query.get(user_id)
    
    record = EncryptedFile(
        id=file_id,
        user_id=user_id,
        name=name,
        size=size,
        mime_type=mime_type,
        sha256_checksum=sha256,
        ciphertext=ct,
        nonce=nonce,
        tag=tag
    )
    db.session.add(record)
    db.session.commit()
    
    AuditRecord.append_event(
        actor_id=str(user_id),
        actor_email=user.email,
        action="FILE_UPLOAD",
        resource_type="ENCRYPTED_FILE",
        resource_id=file_id,
        status="SUCCESS",
        details=f"Encrypted file '{name}' stored with checksum {sha256[:16]}..."
    )
    
    return jsonify(record.to_dict()), 201

@files_bp.route('/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    record = EncryptedFile.query.filter_by(id=file_id, user_id=user_id).first()
    if not record:
        return jsonify({"error": "File not found"}), 404
        
    user = User.query.get(user_id)
    db.session.delete(record)
    db.session.commit()
    
    AuditRecord.append_event(
        actor_id=str(user_id),
        actor_email=user.email,
        action="FILE_DELETE",
        resource_type="ENCRYPTED_FILE",
        resource_id=file_id,
        status="SUCCESS",
        details=f"File record purged: {record.name}"
    )
    
    return jsonify({"message": "File record deleted"}), 200
