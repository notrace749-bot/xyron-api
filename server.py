from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import secrets
import sqlite3
import os
from datetime import datetime

app = FastAPI(title="Xyron License API")

DB = "licenses.db"

# Render Environment Variables bölümündeki değer
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


# ==========================================
# ADMIN AUTH
# ==========================================

def check_admin(x_admin_key: str | None):
    if not ADMIN_KEY:
        raise HTTPException(
            status_code=500,
            detail="Admin key is not configured."
        )

    if not x_admin_key or not secrets.compare_digest(
        x_admin_key,
        ADMIN_KEY
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized."
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

    if row["active"] != 1:
        return {
            "valid": False
        }

    return {
        "valid": True,
        "operator": "Licensed User"
    }


# ==========================================
# CREATE LICENSE
# ==========================================

@app.post("/license/create")
def create_license(
    x_admin_key: str | None = Header(
        default=None,
        alias="X-Admin-Key"
    )
):

    check_admin(x_admin_key)

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
    x_admin_key: str | None = Header(
        default=None,
        alias="X-Admin-Key"
    )
):

    check_admin(x_admin_key)

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
    x_admin_key: str | None = Header(
        default=None,
        alias="X-Admin-Key"
    )
):

    check_admin(x_admin_key)

    key = data.license_key.strip()

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


# ==========================================
# ACTIVATE LICENSE
# ==========================================

@app.post("/license/activate")
def activate_license(
    data: LicenseRequest,
    x_admin_key: str | None = Header(
        default=None,
        alias="X-Admin-Key"
    )
):

    check_admin(x_admin_key)

    key = data.license_key.strip()

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

    changed = cursor.rowcount

    conn.close()

    return {
        "success": changed > 0
    }


# ==========================================
# ADMIN TEST
# ==========================================

@app.get("/admin/panel")
def admin_panel(
    x_admin_key: str | None = Header(
        default=None,
        alias="X-Admin-Key"
    )
):

    check_admin(x_admin_key)

    return {
        "service": "Xyron Admin API",
        "status": "authenticated"
    }
