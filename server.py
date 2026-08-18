from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import secrets
import os
from datetime import datetime

app = FastAPI(title="Xyron License API")

# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# DATABASE
# =========================================================

DB = "licenses.db"

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

# =========================================================
# ADMIN
# =========================================================

ADMIN_KEY = os.getenv("XYRON_ADMIN_KEY", "CHANGE_THIS_ADMIN_KEY")

admin_tokens = set()

# =========================================================
# MODELS
# =========================================================

class LicenseRequest(BaseModel):
    license_key: str


class AdminLoginRequest(BaseModel):
    admin_key: str

# =========================================================
# HELPERS
# =========================================================

def generate_license():
    raw = secrets.token_hex(10).upper()

    return (
        "XYRON-"
        + raw[:4] + "-"
        + raw[4:8] + "-"
        + raw[8:12] + "-"
        + raw[12:16]
    )


def check_admin(authorization):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )

    token = authorization[7:]

    if token not in admin_tokens:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )

    return True

# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return {
        "service": "Xyron License API",
        "status": "online"
    }

# =========================================================
# ADMIN LOGIN
# =========================================================

@app.post("/admin/login")
def admin_login(data: AdminLoginRequest):

    if data.admin_key != ADMIN_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid admin key"
        )

    token = secrets.token_urlsafe(32)

    admin_tokens.add(token)

    return {
        "success": True,
        "token": token
    }

# =========================================================
# LICENSE CHECK
# =========================================================

@app.post("/license/check")
def check_license(data: LicenseRequest):

    key = data.license_key.strip().upper()

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

    if row["active"] != 1:
        return {
            "valid": False
        }

    return {
        "valid": True,
        "operator": "Licensed User"
    }

# =========================================================
# CREATE LICENSE
# =========================================================

@app.post("/license/create")
def create_license(
    authorization: str = Header(None)
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
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "license_key": key
    }

# =========================================================
# LIST LICENSES
# =========================================================

@app.get("/license/list")
def list_licenses(
    authorization: str = Header(None)
):

    check_admin(authorization)

    conn = get_db()

    rows = conn.execute(
        """
        SELECT
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
            "license_key": row["license_key"],
            "active": bool(row["active"]),
            "created_at": row["created_at"]
        })

    return {
        "success": True,
        "licenses": licenses
    }

# =========================================================
# REVOKE LICENSE
# =========================================================

@app.post("/license/revoke")
def revoke_license(
    data: LicenseRequest,
    authorization: str = Header(None)
):

    check_admin(authorization)

    key = data.license_key.strip().upper()

    conn = get_db()

    cursor = conn.execute(
        """
        UPDATE licenses
        SET active = 0
        WHERE license_key = ?
        """,
        (key,)
    )

    conn.commit()

    changed = cursor.rowcount

    conn.close()

    return {
        "success": changed > 0
    }

# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():

    return {
        "status": "ok"
    }
