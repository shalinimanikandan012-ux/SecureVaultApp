
"""
Flask REST API - Authentication Blueprint
User Registration, Argon2id Login, Rate Limiting, and RFC 6238 TOTP
"""

from flask import Blueprint, request, jsonify, session
from datetime import datetime, timedelta, timezone
from app.models.user import User
from app.models.audit import AuditRecord
from app.security.crypto import (
    hash_login_password,
    verify_login_password,
)
from app import db
import pyotp
import hashlib

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not email or not username or not isinstance(password, str) or len(password) < 10:
        return jsonify({
            "error": "Email, username, and a password of at least 10 characters are required"
        }), 400

    if User.query.filter_by(email=email).first():
        return jsonify({
            "error": "An account with this email already exists"
        }), 409

    pwd_hash = hash_login_password(password)

    user = User(
        email=email,
        username=username,
        password_hash=pwd_hash,
        mfa_enabled=False,
        created_at=datetime.now(timezone.utc),
    )

    db.session.add(user)
    db.session.commit()

    AuditRecord.append_event(
        actor_id=str(user.id),
        actor_email=user.email,
        action="USER_REGISTRATION",
        resource_type="USER",
        resource_id=str(user.id),
        status="SUCCESS",
        details=f"User {user.email} registered account",
    )

    return jsonify({
        "message": "Registration successful",
        "user_id": user.id,
        "user": user.to_dict(),
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()
    generic_err = "Invalid email or password."

    if not user:
        return jsonify({"error": generic_err}), 401

    now = datetime.now(timezone.utc)

    if user.lockout_until:
        lockout_until = user.lockout_until

        if lockout_until.tzinfo is None:
            lockout_until = lockout_until.replace(tzinfo=timezone.utc)

        if lockout_until > now:
            remaining = max(
                1,
                int((lockout_until - now).total_seconds() / 60),
            )
            return jsonify({
                "error": f"Account temporarily locked. Try again in {remaining} minutes."
            }), 429

    if not verify_login_password(user.password_hash, password):
        user.failed_login_attempts += 1

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.lockout_until = now + timedelta(
                minutes=LOCKOUT_DURATION_MINUTES
            )

        db.session.commit()

        AuditRecord.append_event(
            actor_id=str(user.id),
            actor_email=user.email,
            action="USER_LOGIN",
            resource_type="SESSION",
            resource_id="pending",
            status="FAILURE",
            details=(
                f"Password check failed for {user.email} "
                f"(Attempt {user.failed_login_attempts})"
            ),
        )

        return jsonify({"error": generic_err}), 401

    user.failed_login_attempts = 0
    user.lockout_until = None
    user.last_login_at = now
    db.session.commit()

    if user.mfa_enabled:
        return jsonify({
            "mfa_required": True,
            "temp_token": f"mfa_{user.id}_{int(now.timestamp())}",
        }), 200

    session["user_id"] = user.id

    AuditRecord.append_event(
        actor_id=str(user.id),
        actor_email=user.email,
        action="USER_LOGIN",
        resource_type="SESSION",
        resource_id=str(user.id),
        status="SUCCESS",
        details=f"User {user.email} logged in successfully",
    )

    return jsonify({
        "message": "Login successful",
        "user": user.to_dict(),
    }), 200


@auth_bp.route("/mfa/verify", methods=["POST"])
def verify_mfa():
    data = request.get_json(silent=True) or {}

    user_id = data.get("user_id")
    code = data.get("code", "").strip()
    recovery_code = data.get("recovery_code", "").strip().upper()

    user = db.session.get(User, user_id) if user_id else None

    if not user or not user.mfa_enabled:
        return jsonify({"error": "Invalid MFA request"}), 400

    if recovery_code:
        code_hash = hashlib.sha256(
            recovery_code.encode("utf-8")
        ).hexdigest()

        hashes = user.get_recovery_hashes()

        if code_hash in hashes:
            hashes.remove(code_hash)
            user.set_recovery_hashes(hashes)
            db.session.commit()

            session["user_id"] = user.id

            AuditRecord.append_event(
                actor_id=str(user.id),
                actor_email=user.email,
                action="MFA_RECOVERY_USED",
                resource_type="SESSION",
                resource_id=str(user.id),
                status="SUCCESS",
                details="Single-use backup code consumed for login",
            )

            return jsonify({
                "message": "Recovery login successful",
                "user": user.to_dict(),
            }), 200

        return jsonify({"error": "Invalid recovery code"}), 401

    if not user.mfa_secret:
        return jsonify({"error": "MFA is not configured correctly"}), 400

    totp = pyotp.TOTP(user.mfa_secret)

    if totp.verify(code, valid_window=1):
        session["user_id"] = user.id

        AuditRecord.append_event(
            actor_id=str(user.id),
            actor_email=user.email,
            action="MFA_VERIFY",
            resource_type="SESSION",
            resource_id=str(user.id),
            status="SUCCESS",
            details="RFC 6238 TOTP verified",
        )

        return jsonify({
            "message": "MFA verified",
            "user": user.to_dict(),
        }), 200

    return jsonify({"error": "Invalid TOTP code"}), 401


@auth_bp.route("/logout", methods=["POST"])
def logout():
    user_id = session.pop("user_id", None)

    if user_id:
        user = db.session.get(User, user_id)

        if user:
            AuditRecord.append_event(
                actor_id=str(user.id),
                actor_email=user.email,
                action="USER_LOGOUT",
                resource_type="SESSION",
                resource_id=str(user.id),
                status="SUCCESS",
                details=f"Session ended for {user.email}",
            )

    return jsonify({"message": "Logged out"}), 200
