
import os
import json
import time
import hmac
import base64
import secrets
import sqlite3

from pathlib import Path
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, send_file, abort
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge


# ---------- APP CONFIGURATION ----------

app = Flask(__name__)

app.secret_key = (
    os.environ.get("SECUREVAULT_SESSION_SECRET")
    or secrets.token_hex(32)
)

app.config["MAX_CONTENT_LENGTH"] = 17 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
DB_PATH = INSTANCE_DIR / "vault.db"

UNLOCKED_KEYS = {}
LOGIN_ATTEMPTS = {}

IDLE_TIMEOUT = 300
MAX_FILE_SIZE = 16 * 1024 * 1024
VERIFIER_TEXT = b"SecureVault password verification v1"


# ---------- DATABASE ----------

def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                payload BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def vault_is_setup():
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM settings WHERE id = 1"
        ).fetchone()

    return row is not None


# ---------- PASSWORD KEY DERIVATION ----------

def derive_key(password, salt):
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )


# ---------- AES-256-GCM ENCRYPTION ----------

def encrypt_bytes(key, plaintext):
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_bytes(key, encrypted):
    if len(encrypted) < 29:
        raise ValueError("Invalid encrypted data")

    nonce = encrypted[:12]
    ciphertext = encrypted[12:]

    return AESGCM(key).decrypt(nonce, ciphertext, None)


def encrypt_json(key, data):
    raw = json.dumps(data).encode("utf-8")
    return encrypt_bytes(key, raw)


def decrypt_json(key, encrypted):
    raw = decrypt_bytes(key, encrypted)
    return json.loads(raw.decode("utf-8"))


# ---------- CSRF PROTECTION ----------

def csrf_token():
    token = session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token

    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    if request.method != "POST":
        return None

    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "")

    if not expected or not supplied:
        abort(
            400,
            description="Missing security token. Refresh the page and try again."
        )

    if not hmac.compare_digest(expected, supplied):
        abort(
            400,
            description="Security token mismatch. Refresh the page and try again."
        )


# ---------- UNLOCKED VAULT SESSION ----------

def get_unlocked_key():
    sid = session.get("sid")
    entry = UNLOCKED_KEYS.get(sid)

    if not entry:
        return None

    if time.time() - entry["last_seen"] > IDLE_TIMEOUT:
        UNLOCKED_KEYS.pop(sid, None)
        return None

    entry["last_seen"] = time.time()
    return entry["key"]


def require_unlock(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if get_unlocked_key() is None:
            session.pop("sid", None)
            flash(
                "Vault locked. Enter your master password again.",
                "error"
            )
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def create_unlocked_session(key):
    session.clear()

    sid = secrets.token_urlsafe(32)
    session["sid"] = sid
    session["csrf_token"] = secrets.token_urlsafe(32)

    UNLOCKED_KEYS[sid] = {
        "key": key,
        "last_seen": time.time()
    }


# ---------- LOGIN AND FIRST-TIME SETUP ----------

@app.route("/", methods=["GET", "POST"])
def login():
    is_setup = vault_is_setup()

    if request.method == "POST":
        ip = request.remote_addr or "local"
        now = time.time()

        attempts, locked_until = LOGIN_ATTEMPTS.get(ip, (0, 0))

        if now < locked_until:
            flash("Too many attempts. Please wait a minute.", "error")
            return render_template("login.html", is_setup=is_setup)

        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not password:
            flash("Enter your master password.", "error")
            return render_template("login.html", is_setup=is_setup)

        # FIRST-TIME VAULT SETUP
        if not is_setup:
            if len(password) < 12:
                flash(
                    "Use a master password with at least 12 characters.",
                    "error"
                )
                return render_template("login.html", is_setup=True)

            if password != confirm:
                flash("The passwords do not match.", "error")
                return render_template("login.html", is_setup=True)

            salt = secrets.token_bytes(16)
            key = derive_key(password, salt)

            # Store an encrypted verifier, not the password or raw key.
            verifier = encrypt_bytes(key, VERIFIER_TEXT)

            with get_db() as db:
                db.execute(
                    """
                    INSERT INTO settings (id, salt, verifier)
                    VALUES (1, ?, ?)
                    """,
                    (salt, verifier)
                )

            LOGIN_ATTEMPTS.pop(ip, None)
            create_unlocked_session(key)

            flash("Vault created successfully!", "success")
            return redirect(url_for("dashboard"))

        # EXISTING VAULT LOGIN
        with get_db() as db:
            settings = db.execute(
                "SELECT salt, verifier FROM settings WHERE id = 1"
            ).fetchone()

        try:
            key = derive_key(password, settings["salt"])
            verified = decrypt_bytes(key, settings["verifier"])

            if not hmac.compare_digest(verified, VERIFIER_TEXT):
                raise ValueError("Verification failed")

        except Exception:
            attempts += 1
            locked_until = now + 60 if attempts >= 5 else 0
            LOGIN_ATTEMPTS[ip] = (attempts, locked_until)

            flash("Incorrect master password.", "error")
            return render_template("login.html", is_setup=False)

        LOGIN_ATTEMPTS.pop(ip, None)
        create_unlocked_session(key)

        flash("Vault unlocked.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", is_setup=is_setup)


# ---------- DASHBOARD ----------

@app.route("/dashboard")
@require_unlock
def dashboard():
    key = get_unlocked_key()
    notes = []
    files = []

    with get_db() as db:
        rows = db.execute(
            """
            SELECT id, kind, payload, created_at
            FROM records
            ORDER BY id DESC
            """
        ).fetchall()

    for row in rows:
        try:
            item = decrypt_json(key, row["payload"])
        except Exception:
            continue

        if row["kind"] == "note":
            notes.append({
                "id": row["id"],
                "title": item.get("title", "Untitled"),
                "content": item.get("content", ""),
                "created_at": row["created_at"]
            })

        elif row["kind"] == "file":
            files.append({
                "id": row["id"],
                "name": item.get("name", "file"),
                "created_at": row["created_at"]
            })

    return render_template(
        "dashboard.html",
        notes=notes,
        files=files,
        note_count=len(notes),
        file_count=len(files)
    )


# ---------- ADD ENCRYPTED NOTE ----------

@app.route("/add_note", methods=["POST"])
@require_unlock
def add_note():
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    if not title or not content:
        flash("Enter both a note title and its content.", "error")
        return redirect(url_for("dashboard"))

    if len(title) > 150 or len(content) > 20000:
        flash("The title or note is too long.", "error")
        return redirect(url_for("dashboard"))

    key = get_unlocked_key()

    payload = encrypt_json(key, {
        "title": title,
        "content": content
    })

    created_at = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            """
            INSERT INTO records (kind, payload, created_at)
            VALUES (?, ?, ?)
            """,
            ("note", payload, created_at)
        )

    flash("Encrypted note saved.", "success")
    return redirect(url_for("dashboard"))


# ---------- ENCRYPT AND UPLOAD FILE ----------

@app.route("/upload_file", methods=["POST"])
@require_unlock
def upload_file():
    uploaded = request.files.get("file")

    if not uploaded or not uploaded.filename:
        flash("Choose a file to upload.", "error")
        return redirect(url_for("dashboard"))

    filename = secure_filename(uploaded.filename)

    if not filename:
        flash("Invalid file name.", "error")
        return redirect(url_for("dashboard"))

    file_data = uploaded.read(MAX_FILE_SIZE + 1)

    if not file_data:
        flash("The selected file is empty.", "error")
        return redirect(url_for("dashboard"))

    if len(file_data) > MAX_FILE_SIZE:
        flash("Maximum file size is 16 MB.", "error")
        return redirect(url_for("dashboard"))

    key = get_unlocked_key()

    payload = encrypt_json(key, {
        "name": filename,
        "content_type": "application/octet-stream",
        "data": base64.b64encode(file_data).decode("ascii")
    })

    created_at = datetime.now(timezone.utc).isoformat()

    with get_db() as db:
        db.execute(
            """
            INSERT INTO records (kind, payload, created_at)
            VALUES (?, ?, ?)
            """,
            ("file", payload, created_at)
        )

    flash("File encrypted and stored in the vault.", "success")
    return redirect(url_for("dashboard"))


# ---------- DOWNLOAD AND DECRYPT FILE ----------

@app.route("/download_file/<int:record_id>")
@require_unlock
def download_file(record_id):
    key = get_unlocked_key()

    with get_db() as db:
        row = db.execute(
            """
            SELECT payload
            FROM records
            WHERE id = ? AND kind = 'file'
            """,
            (record_id,)
        ).fetchone()

    if row is None:
        abort(404)

    try:
        item = decrypt_json(key, row["payload"])
        data = base64.b64decode(item["data"], validate=True)
    except Exception:
        abort(400, description="Unable to decrypt this file.")

    return send_file(
        BytesIO(data),
        as_attachment=True,
        download_name=item.get("name", "download.bin"),
        mimetype="application/octet-stream"
    )


# ---------- DELETE NOTE OR FILE ----------

@app.route("/delete_record/<int:record_id>", methods=["POST"])
@require_unlock
def delete_record(record_id):
    with get_db() as db:
        result = db.execute(
            "DELETE FROM records WHERE id = ?",
            (record_id,)
        )

    if result.rowcount:
        flash("Record deleted.", "success")
    else:
        flash("Record not found.", "error")

    return redirect(url_for("dashboard"))


# ---------- LOCK / LOGOUT ----------

@app.route("/logout", methods=["POST"])
def logout():
    sid = session.get("sid")

    if sid:
        UNLOCKED_KEYS.pop(sid, None)

    session.clear()
    flash("Vault locked.", "success")
    return redirect(url_for("login"))


# ---------- UPLOAD SIZE ERROR ----------

@app.errorhandler(RequestEntityTooLarge)
def too_large(error):
    flash("Upload is too large. Maximum file size is 16 MB.", "error")

    if get_unlocked_key() is not None:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ---------- START APPLICATION ----------

init_db()

if __name__ == "__main__":
    app.run(debug=True)
