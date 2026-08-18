from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import secrets
from datetime import datetime

app = FastAPI(title="Xyron API")

# =========================================================
# AYARLAR
# =========================================================

DB = "licenses.db"

# BURAYI KENDİ ADMIN ŞİFRENLE DEĞİŞTİR
ADMIN_KEY = "XYRON_ADMIN_123456"

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
# ADMIN OTURUMLARI
# =========================================================

admin_tokens = set()

# =========================================================
# DATABASE
# =========================================================

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
            created_at TEXT NOT NULL,
            used_at TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()

# =========================================================
# MODELLER
# =========================================================

class LicenseRequest(BaseModel):
    license_key: str


class AdminLoginRequest(BaseModel):
    admin_key: str


# =========================================================
# LICENSE OLUŞTURMA
# =========================================================

def generate_license():

    raw = secrets.token_hex(8).upper()

    return (
        "XYRON-"
        + raw[0:4] + "-"
        + raw[4:8] + "-"
        + raw[8:12] + "-"
        + raw[12:16]
    )


# =========================================================
# ADMIN KONTROL
# =========================================================

def require_admin(authorization):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization required"
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization"
        )

    token = authorization[7:].strip()

    if token not in admin_tokens:
        raise HTTPException(
            status_code=401,
            detail="Invalid admin token"
        )


# =========================================================
# LICENSE KONTROL
# =========================================================

def is_valid_license(key):

    key = key.strip().upper()

    if not key:
        return False

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
        return False

    return int(row["active"]) == 1


# =========================================================
# API TEST
# =========================================================

@app.get("/")
def home():

    return {
        "service": "Xyron API",
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
# LICENSE CREATE
# =========================================================

@app.post("/license/create")
def create_license(
    authorization: str | None = Header(default=None)
):

    require_admin(authorization)

    conn = get_db()

    # Benzersiz key üret
    while True:

        key = generate_license()

        exists = conn.execute(
            """
            SELECT id
            FROM licenses
            WHERE license_key = ?
            """,
            (key,)
        ).fetchone()

        if not exists:
            break

    conn.execute(
        """
        INSERT INTO licenses
        (
            license_key,
            active,
            created_at,
            used_at
        )
        VALUES (?, 1, ?, NULL)
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
# LICENSE CHECK
# =========================================================

@app.post("/license/check")
def check_license(data: LicenseRequest):

    key = data.license_key.strip().upper()

    if not key:

        return {
            "valid": False
        }

    conn = get_db()

    row = conn.execute(
        """
        SELECT license_key, active
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

    if int(row["active"]) != 1:

        return {
            "valid": False
        }

    return {
        "valid": True
    }


# =========================================================
# LICENSE LIST
# =========================================================

@app.get("/license/list")
def list_licenses(
    authorization: str | None = Header(default=None)
):

    require_admin(authorization)

    conn = get_db()

    rows = conn.execute(
        """
        SELECT
            license_key,
            active,
            created_at,
            used_at
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
            "created_at": row["created_at"],
            "used_at": row["used_at"]
        })

    return {
        "licenses": licenses
    }


# =========================================================
# LICENSE REVOKE
# =========================================================

@app.post("/license/revoke")
def revoke_license(
    data: LicenseRequest,
    authorization: str | None = Header(default=None)
):

    require_admin(authorization)

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
    conn.close()

    return {
        "success": cursor.rowcount > 0
    }


# =========================================================
# LICENSE ACTIVATE
# =========================================================

@app.post("/license/activate")
def activate_license(
    data: LicenseRequest,
    authorization: str | None = Header(default=None)
):

    require_admin(authorization)

    key = data.license_key.strip().upper()

    conn = get_db()

    cursor = conn.execute(
        """
        UPDATE licenses
        SET active = 1
        WHERE license_key = ?
        """,
        (key,)
    )

    conn.commit()
    conn.close()

    return {
        "success": cursor.rowcount > 0
    }


# =========================================================
# LOGOUT
# =========================================================

@app.post("/admin/logout")
def admin_logout(
    authorization: str | None = Header(default=None)
):

    if authorization and authorization.startswith("Bearer "):

        token = authorization[7:].strip()

        admin_tokens.discard(token)

    return {
        "success": True
    }
