from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import secrets
import sqlite3
from datetime import datetime

app = FastAPI(title="Xyron API")

DB = "licenses.db"

# BUNU DEĞİŞTİR
ADMIN_KEY = "XYRON_CHANGE_THIS_ADMIN_KEY"

admin_tokens = set()


def db():
    return sqlite3.connect(DB)


def init_db():
    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            detections INTEGER NOT NULL,
            results TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


class LicenseRequest(BaseModel):
    license_key: str


class AdminLoginRequest(BaseModel):
    admin_key: str


class ScanReport(BaseModel):
    license_key: str
    status: str
    detections: int
    results: list


def generate_license():
    raw = secrets.token_hex(16).upper()

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
            detail="Invalid admin token"
        )


@app.get("/")
def home():
    return {
        "service": "Xyron API",
        "status": "online"
    }


@app.post("/license/check")
def check_license(data: LicenseRequest):

    conn = db()

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
        "valid": bool(
            row and row[0] == 1
        )
    }


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
        "token": token
    }


@app.post("/license/create")
def create_license(
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    key = generate_license()

    conn = db()

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


@app.get("/license/list")
def list_licenses(
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    conn = db()

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


@app.post("/license/revoke")
def revoke_license(
    data: LicenseRequest,
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    conn = db()

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


@app.post("/scan/report")
def scan_report(data: ScanReport):

    conn = db()

    license_row = conn.execute(
        """
        SELECT active
        FROM licenses
        WHERE license_key = ?
        """,
        (data.license_key.strip(),)
    ).fetchone()

    if not license_row or license_row[0] != 1:
        conn.close()

        raise HTTPException(
            status_code=403,
            detail="Invalid license"
        )

    import json

    conn.execute(
        """
        INSERT INTO scan_results
        (
            license_key,
            created_at,
            status,
            detections,
            results
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            data.license_key.strip(),
            datetime.now().isoformat(),
            data.status,
            data.detections,
            json.dumps(
                data.results,
                ensure_ascii=False
            )
        )
    )

    conn.commit()
    conn.close()

    return {
        "success": True
    }


@app.get("/admin/scans")
def get_scans(
    authorization: str | None = Header(default=None)
):

    check_admin(authorization)

    conn = db()

    rows = conn.execute(
        """
        SELECT
            id,
            license_key,
            created_at,
            status,
            detections,
            results
        FROM scan_results
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    import json

    return {
        "scans": [
            {
                "id": row[0],
                "license_key": row[1],
                "created_at": row[2],
                "status": row[3],
                "detections": row[4],
                "results": json.loads(row[5])
            }
            for row in rows
        ]
        for row in rows
    }
