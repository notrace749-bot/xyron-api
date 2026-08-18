from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import secrets
import sqlite3
import os
import time
import hashlib
import hmac
import base64
import json
from datetime import datetime

app = FastAPI(title="Xyron License API")

DB = "licenses.db"

ADMIN_KEY = os.environ.get("XYRON_ADMIN_KEY", "")


# ==========================================
# DATABASE
# ==========================================

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ==========================================
# MODELS
# ==========================================

class LicenseRequest(BaseModel):
    license_key: str


class LoginRequest(BaseModel):
    admin_key: str


# ==========================================
# AUTH
# ==========================================

def create_token():

    payload = {
        "type": "admin",
        "exp": int(time.time()) + 60 * 60 * 12
    }

    payload_json = json.dumps(
        payload,
        separators=(",", ":")
    ).encode()

    payload_encoded = base64.urlsafe_b64encode(
        payload_json
    ).decode().rstrip("=")

    signature = hmac.new(
        ADMIN_KEY.encode(),
        payload_encoded.encode(),
        hashlib.sha256
    ).hexdigest()

    return payload_encoded + "." + signature


def verify_token(token):

    if not token:
        return False

    try:

        parts = token.split(".")

        if len(parts) != 2:
            return False

        payload_encoded = parts[0]
        received_signature = parts[1]

        expected_signature = hmac.new(
            ADMIN_KEY.encode(),
            payload_encoded.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            received_signature,
            expected_signature
        ):
            return False

        padding = "=" * (
            4 - len(payload_encoded) % 4
        )

        payload_json = base64.urlsafe_b64decode(
            payload_encoded + padding
        )

        payload = json.loads(
            payload_json.decode()
        )

        if payload.get("type") != "admin":
            return False

        if payload.get("exp", 0) < int(time.time()):
            return False

        return True

    except Exception:
        return False


def check_admin(authorization):

    if not ADMIN_KEY:
        raise HTTPException(
            status_code=500,
            detail="XYRON_ADMIN_KEY is not configured."
        )

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization required."
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization."
        )

    token = authorization[7:]

    if not verify_token(token):
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid."
        )


# ==========================================
# LICENSE GENERATOR
# ==========================================

def generate_license():

    while True:

        raw = secrets.token_hex(16).upper()

        key = (
            "XYRON-"
            + raw[:4] + "-"
            + raw[4:8] + "-"
            + raw[8:12] + "-"
            + raw[12:16]
        )

        conn = get_db()

        exists = conn.execute(
            """
            SELECT id
            FROM licenses
            WHERE license_key = ?
            """,
            (key,)
        ).fetchone()

        conn.close()

        if exists is None:
            return key


# ==========================================
# HOME
# ==========================================

@app.get("/")
def home():

    return {
        "service": "Xyron License API",
        "status": "online"
    }


# ==========================================
# ADMIN LOGIN
# ==========================================

@app.post("/admin/login")
def admin_login(data: LoginRequest):

    if not ADMIN_KEY:
        raise HTTPException(
            status_code=500,
            detail="Admin key is not configured."
        )

    if not secrets.compare_digest(
        data.admin_key,
        ADMIN_KEY
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid admin key."
        )

    return {
        "success": True,
        "token": create_token()
    }


# ==========================================
# ADMIN CHECK
# ==========================================

@app.get("/admin/panel")
def admin_panel(
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    return {
        "success": True,
        "status": "authenticated"
    }


# ==========================================
# LICENSE CHECK
# ==========================================

@app.post("/license/check")
def check_license(data: LicenseRequest):

    key = data.license_key.strip()

    if not key:
        return {
            "valid": False
        }

    conn = get_db()

    row = conn.execute(
        """
        SELECT active
        FROM licenses
        WHERE license_key = ?
        """,
        (key,)
    ).fetchone()

    conn.close()

    if row is None:
        return {
            "valid": False
        }

    return {
        "valid": row["active"] == 1,
        "operator": "Licensed User"
    }


# ==========================================
# CREATE LICENSE
# ==========================================

@app.post("/license/create")
def create_license(
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    key = generate_license()

    conn = get_db()

    conn.execute(
        """
        INSERT INTO licenses
        (license_key, active, created_at)
        VALUES (?, 1, ?)
        """,
        (
            key,
            datetime.now().isoformat()
        )
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "license_key": key
    }


# ==========================================
# LIST LICENSES
# ==========================================

@app.get("/license/list")
def list_licenses(
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    conn = get_db()

    rows = conn.execute(
        """
        SELECT
            id,
            license_key,
            active,
            created_at
        FROM licenses
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    licenses = []

    for row in rows:

        licenses.append({
            "id": row["id"],
            "license_key": row["license_key"],
            "active": bool(row["active"]),
            "created_at": row["created_at"]
        })

    return {
        "success": True,
        "licenses": licenses
    }


# ==========================================
# REVOKE LICENSE
# ==========================================

@app.post("/license/revoke")
def revoke_license(
    data: LicenseRequest,
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    conn = get_db()

    cursor = conn.execute(
        """
        UPDATE licenses
        SET active = 0
        WHERE license_key = ?
        """,
        (data.license_key.strip(),)
    )

    conn.commit()

    changed = cursor.rowcount

    conn.close()

    return {
        "success": changed > 0
    }


# ==========================================
# ACTIVATE LICENSE
# ==========================================

@app.post("/license/activate")
def activate_license(
    data: LicenseRequest,
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    conn = get_db()

    cursor = conn.execute(
        """
        UPDATE licenses
        SET active = 1
        WHERE license_key = ?
        """,
        (data.license_key.strip(),)
    )

    conn.commit()

    changed = cursor.rowcount

    conn.close()

    return {
        "success": changed > 0
    }
