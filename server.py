from fastapi import FastAPI
from pydantic import BaseModel
import secrets
import hashlib
import sqlite3
from datetime import datetime

app = FastAPI(title="Xyron License API")

DB = "licenses.db"


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

    key = data.license_key.strip()

    conn = sqlite3.connect(DB)

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

    if row[0] != 1:
        return {
            "valid": False
        }

    return {
        "valid": True,
        "operator": "Licensed User"
    }


@app.post("/license/create")
def create_license():

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
        "license_key": key
    }


@app.post("/license/revoke")
def revoke_license(data: LicenseRequest):

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

    changed = cursor.rowcount

    conn.close()

    return {
        "success": changed > 0
    }