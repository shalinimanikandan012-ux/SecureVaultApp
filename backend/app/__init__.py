"""
SecureVaultApp - Flask Application Factory & Middleware
"""

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv()

db = SQLAlchemy()

def create_app(config_override=None):
    app = Flask(__name__)
    
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')
    database_url = os.getenv('DATABASE_URL', 'sqlite:///securevault.db')
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
        
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 15 * 1024 * 1024))

    if config_override:
        app.config.update(config_override)

    # Initialize extensions
    db.init_app(app)
    
    frontend_origin = os.getenv('FRONTEND_ORIGIN', 'http://localhost:3000')
    CORS(app, origins=[frontend_origin], supports_credentials=True)

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

    # Global Error Handlers (Safe error responses that never leak stack traces)
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request", "message": str(e)}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "Internal server error"}), 500

    # Register Blueprints
    from app.api.auth import auth_bp
    from app.api.vault import vault_bp
    from app.api.notes import notes_bp
    from app.api.files import files_bp
    from app.api.forensics import forensics_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(vault_bp)
    app.register_blueprint(notes_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(forensics_bp)

    @app.route('/health')
    def health():
        return jsonify({"status": "healthy", "service": "SecureVaultApp API"}), 200

    with app.app_context():
        db.create_all()

    return app
