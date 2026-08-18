from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import secrets
import sqlite3
from datetime import datetime

app = FastAPI(title="Xyron License API")

DB = "licenses.db"

ADMIN_KEY = "XYRON_ADMIN_KEY"


def init_db():
    conn = sqlite3.connect(DB)

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


class LicenseRequest(BaseModel):
    license_key: str


class AdminLoginRequest(BaseModel):
    admin_key: str


def generate_license():
    raw = secrets.token_hex(16).upper()

    return (
        "XYRON-"
        + raw[:4] + "-"
        + raw[4:8] + "-"
        + raw[8:12] + "-"
        + raw[12:16]
    )


@app.get("/")
def home():
    return {
        "service": "Xyron License API",
        "status": "online"
    }


@app.post("/license/check")
def check_license(data: LicenseRequest):

    conn = sqlite3.connect(DB)

    row = conn.execute(
        """
        SELECT active
        FROM licenses
        WHERE license_key = ?
        """,
        (data.license_key.strip(),)
    ).fetchone()

    conn.close()

    return {
        "valid": row is not None and row[0] == 1
    }


@app.post("/admin/login")
def admin_login(data: AdminLoginRequest):

    if data.admin_key != ADMIN_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid admin key"
        )

    token = secrets.token_urlsafe(32)

    return {
        "token": token
    }


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

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )


@app.get("/license/list")
def list_licenses(
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    conn = sqlite3.connect(DB)

    rows = conn.execute(
        """
        SELECT license_key, active, created_at
        FROM licenses
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    return {
        "licenses": [
            {
                "license_key": row[0],
                "active": bool(row[1]),
                "created_at": row[2]
            }
            for row in rows
        ]
    }


@app.post("/license/create")
def create_license(
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    key = generate_license()

    conn = sqlite3.connect(DB)

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


@app.post("/license/revoke")
def revoke_license(
    data: LicenseRequest,
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    conn = sqlite3.connect(DB)

    cursor = conn.execute(
        """
        UPDATE licenses
        SET active = 0
        WHERE license_key = ?
        """,
        (data.license_key.strip(),)
    )

    conn.commit()
    conn.close()

    return {
        "success": cursor.rowcount > 0
    }
