"""
Flask REST API - Encrypted Notes Blueprint
CRUD operations for zero-knowledge AES-256-GCM note records
"""

from flask import Blueprint, request, jsonify, session
from app.models.vault import EncryptedNote
from app.models.user import User
from app.models.audit import AuditRecord
from app import db
import json
import uuid

notes_bp = Blueprint('notes', __name__, url_prefix='/api/notes')

@notes_bp.route('', methods=['GET'])
def list_notes():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    notes = EncryptedNote.query.filter_by(user_id=user_id).order_by(EncryptedNote.updated_at.desc()).all()
    return jsonify([n.to_dict() for n in notes]), 200

@notes_bp.route('', methods=['POST'])
def create_note():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    category = data.get('category', 'Confidential').strip()
    tags = data.get('tags', [])
    payload = data.get('encrypted_payload', {})
    
    ct = payload.get('ciphertext')
    nonce = payload.get('nonce')
    tag = payload.get('tag')
    
    if not title or not ct or not nonce or not tag:
        return jsonify({"error": "Invalid payload format"}), 400
        
    note_id = str(uuid.uuid4())
    user = User.query.get(user_id)
    
    note = EncryptedNote(
        id=note_id,
        user_id=user_id,
        title=title,
        category=category,
        tags=json.dumps(tags),
        ciphertext=ct,
        nonce=nonce,
        tag=tag
    )
    db.session.add(note)
    db.session.commit()
    
    AuditRecord.append_event(
        actor_id=str(user_id),
        actor_email=user.email,
        action="NOTE_CREATE",
        resource_type="NOTE",
        resource_id=note_id,
        status="SUCCESS",
        details=f"Encrypted note '{title}' created"
    )
    
    return jsonify(note.to_dict()), 201

@notes_bp.route('/<note_id>', methods=['DELETE'])
def delete_note(note_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
        
    note = EncryptedNote.query.filter_by(id=note_id, user_id=user_id).first()
    if not note:
        return jsonify({"error": "Note not found"}), 404
        
    user = User.query.get(user_id)
    db.session.delete(note)
    db.session.commit()
    
    AuditRecord.append_event(
        actor_id=str(user_id),
        actor_email=user.email,
        action="NOTE_DELETE",
        resource_type="NOTE",
        resource_id=note_id,
        status="SUCCESS",
        details="Encrypted note purged from database"
    )
    
    return jsonify({"message": "Note deleted"}), 200
