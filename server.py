from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import secrets
import sqlite3
import json
from datetime import datetime

app = FastAPI(title="Xyron API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "licenses.db"

ADMIN_KEY = "XYRON_CHANGE_THIS_ADMIN_KEY"

admin_tokens = set()

app = FastAPI(title="Xyron API")

# CORS
# Web sitenin API'ye istek göndermesine izin verir.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "licenses.db"

ADMIN_KEY = "XYRON_CHANGE_THIS_ADMIN_KEY"

admin_tokens = set()


def get_db():
    return sqlite3.connect(DB)


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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            detections INTEGER NOT NULL,
            results TEXT NOT NULL
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
        + raw[0:4] + "-"
        + raw[4:8] + "-"
        + raw[8:12] + "-"
        + raw[12:16]
    )


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


def is_valid_license(key):

    conn = get_db()

    row = conn.execute(
        """
        SELECT active
        FROM licenses
        WHERE license_key = ?
        """,
        (key.strip(),)
    ).fetchone()

    conn.close()

    return bool(row and row[0] == 1)


@app.get("/")
def home():

    return {
        "service": "Xyron API",
        "status": "online"
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
        "success": True,
        "token": token
    }


@app.post("/license/create")
def create_license(
    authorization: str | None = Header(default=None)
):

    require_admin(authorization)

    key = generate_license()

    conn = get_db()

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
            datetime.now().isoformat()
        )
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "license_key": key
    }


@app.post("/license/use")
def use_license(data: LicenseRequest):

    key = data.license_key.strip()

    conn = get_db()

    row = conn.execute(
        """
        SELECT active
        FROM licenses
        WHERE license_key = ?
        """,
        (key,)
    ).fetchone()

    if not row or row[0] != 1:

        conn.close()

        raise HTTPException(
            status_code=403,
            detail="Invalid or already used license"
        )

    new_key = generate_license()

    conn.execute(
        """
        UPDATE licenses
        SET active = 0,
            used_at = ?
        WHERE license_key = ?
        """,
        (
            datetime.now().isoformat(),
            key
        )
    )

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
            new_key,
            datetime.now().isoformat()
        )
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "old_key": key,
        "new_key": new_key
    }


@app.post("/license/check")
def check_license(data: LicenseRequest):

    return {
        "valid": is_valid_license(
            data.license_key
        )
    }


@app.post("/license/revoke")
def revoke_license(
    data: LicenseRequest,
    authorization: str | None = Header(default=None)
):

    require_admin(authorization)

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
    conn.close()

    return {
        "success": cursor.rowcount > 0
    }


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

    return {
        "licenses": [
            {
                "license_key": row[0],
                "active": bool(row[1]),
                "created_at": row[2],
                "used_at": row[3]
            }
            for row in rows
        ]
    }


@app.post("/scan/report")
def scan_report(data: ScanReport):

    if not is_valid_license(
        data.license_key
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid license"
        )

    conn = get_db()

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
def admin_scans(
    authorization: str | None = Header(default=None)
):

    require_admin(authorization)

    conn = get_db()

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

    scans = []

    for row in rows:

        try:
            results = json.loads(row[5])
        except Exception:
            results = []

        scans.append({
            "id": row[0],
            "license_key": row[1],
            "created_at": row[2],
            "status": row[3],
            "detections": row[4],
            "results": results
        })

    return {
        "scans": scans
    }
