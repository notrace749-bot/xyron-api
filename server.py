from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import secrets
import sqlite3
import json
from datetime import datetime


app = FastAPI(
    title="Xyron Security API"
)


DB = "licenses.db"

ADMIN_KEY = "XYRON_ADMIN_KEY"


# =========================================================
# DATABASE
# =========================================================

def get_db():

    conn = sqlite3.connect(
        DB,
        check_same_thread=False
    )

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

    conn.execute("""
        CREATE TABLE IF NOT EXISTS admin_tokens (
            token TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            scanner_version TEXT,
            timestamp TEXT NOT NULL,
            files_scanned INTEGER DEFAULT 0,
            detections_json TEXT,
            processes_json TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# MODELS
# =========================================================

class LicenseRequest(BaseModel):

    license_key: str


class AdminLoginRequest(BaseModel):

    admin_key: str


class ScanResult(BaseModel):

    license_key: str

    scanner: str = "Xyron"

    version: str = "3.0"

    timestamp: str = ""

    files_scanned: int = 0

    detections: list = []

    processes: list = []


# =========================================================
# LICENSE
# =========================================================

def generate_license():

    raw = secrets.token_hex(
        16
    ).upper()

    return (
        "XYRON-"
        + raw[0:4]
        + "-"
        + raw[4:8]
        + "-"
        + raw[8:12]
        + "-"
        + raw[12:16]
    )


@app.post("/license/check")
def check_license(
    data: LicenseRequest
):

    conn = get_db()

    row = conn.execute(
        """
        SELECT active
        FROM licenses
        WHERE license_key = ?
        """,
        (
            data.license_key.strip(),
        )
    ).fetchone()

    conn.close()

    return {
        "valid":
            row is not None
            and row["active"] == 1
    }


# =========================================================
# ADMIN AUTH
# =========================================================

@app.post("/admin/login")
def admin_login(
    data: AdminLoginRequest
):

    if data.admin_key != ADMIN_KEY:

        raise HTTPException(
            status_code=401,
            detail="Invalid admin key"
        )

    token = secrets.token_urlsafe(
        32
    )

    conn = get_db()

    conn.execute(
        """
        INSERT INTO admin_tokens
        (token, created_at)
        VALUES (?, ?)
        """,
        (
            token,
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "token": token
    }


def check_admin(
    authorization
):

    if not authorization:

        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )

    if not authorization.startswith(
        "Bearer "
    ):

        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )

    token = authorization[
        7:
    ].strip()

    if not token:

        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )

    conn = get_db()

    row = conn.execute(
        """
        SELECT token
        FROM admin_tokens
        WHERE token = ?
        """,
        (
            token,
        )
    ).fetchone()

    conn.close()

    if row is None:

        raise HTTPException(
            status_code=401,
            detail="Invalid admin token"
        )

    return True


# =========================================================
# LICENSE ADMIN
# =========================================================

@app.get("/license/list")
def list_licenses(
    authorization: str | None = Header(
        default=None
    )
):

    check_admin(
        authorization
    )

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

    return {
        "licenses": [
            {
                "license_key":
                    row["license_key"],

                "active":
                    bool(
                        row["active"]
                    ),

                "created_at":
                    row["created_at"]
            }

            for row in rows
        ]
    }


@app.post("/license/create")
def create_license(
    authorization: str | None = Header(
        default=None
    )
):

    check_admin(
        authorization
    )

    key = generate_license()

    conn = get_db()

    conn.execute(
        """
        INSERT INTO licenses
        (
            license_key,
            active,
            created_at
        )
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


@app.post("/license/revoke")
def revoke_license(
    data: LicenseRequest,
    authorization: str | None = Header(
        default=None
    )
):

    check_admin(
        authorization
    )

    conn = get_db()

    cursor = conn.execute(
        """
        UPDATE licenses
        SET active = 0
        WHERE license_key = ?
        """,
        (
            data.license_key.strip(),
        )
    )

    conn.commit()
    conn.close()

    return {
        "success":
            cursor.rowcount > 0
    }


# =========================================================
# SCAN RESULT
# =========================================================

@app.post("/scan/result")
def receive_scan(
    data: ScanResult
):

    license_key = (
        data.license_key.strip()
    )

    if not license_key:

        raise HTTPException(
            status_code=400,
            detail="License key required"
        )

    # -----------------------------------------------------
    # Check license
    # -----------------------------------------------------

    conn = get_db()

    license_row = conn.execute(
        """
        SELECT active
        FROM licenses
        WHERE license_key = ?
        """,
        (
            license_key,
        )
    ).fetchone()

    if (
        license_row is None
        or license_row["active"] != 1
    ):

        conn.close()

        raise HTTPException(
            status_code=403,
            detail="Invalid license"
        )

    # -----------------------------------------------------
    # Store scan
    # -----------------------------------------------------

    timestamp = (
        data.timestamp
        or datetime.utcnow().isoformat()
    )

    conn.execute(
        """
        INSERT INTO scans
        (
            license_key,
            scanner_version,
            timestamp,
            files_scanned,
            detections_json,
            processes_json
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            license_key,

            data.version,

            timestamp,

            data.files_scanned,

            json.dumps(
                data.detections,
                ensure_ascii=False
            ),

            json.dumps(
                data.processes,
                ensure_ascii=False
            )
        )
    )

    scan_id = conn.execute(
        "SELECT last_insert_rowid()"
    ).fetchone()[0]

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message":
            "Scan result received",
        "scan_id":
            scan_id
    }


# =========================================================
# ADMIN SCAN LIST
# =========================================================

@app.get("/admin/scans")
def list_scans(
    authorization: str | None = Header(
        default=None
    )
):

    check_admin(
        authorization
    )

    conn = get_db()

    rows = conn.execute(
        """
        SELECT
            id,
            license_key,
            scanner_version,
            timestamp,
            files_scanned,
            detections_json,
            processes_json
        FROM scans
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    result = []

    for row in rows:

        detections = json.loads(
            row["detections_json"]
            or "[]"
        )

        processes = json.loads(
            row["processes_json"]
            or "[]"
        )

        high = sum(
            1
            for item in detections
            if item.get("risk") == "HIGH"
        )

        review = sum(
            1
            for item in detections
            if item.get("risk") == "REVIEW"
        )

        result.append({

            "id":
                row["id"],

            "license_key":
                row["license_key"],

            "scanner_version":
                row["scanner_version"],

            "timestamp":
                row["timestamp"],

            "files_scanned":
                row["files_scanned"],

            "detection_count":
                len(detections),

            "high":
                high,

            "review":
                review,

            "process_count":
                len(processes)

        })

    return {
        "scans": result
    }


# =========================================================
# ADMIN SCAN DETAIL
# =========================================================

@app.get("/admin/scans/{scan_id}")
def scan_detail(
    scan_id: int,
    authorization: str | None = Header(
        default=None
    )
):

    check_admin(
        authorization
    )

    conn = get_db()

    row = conn.execute(
        """
        SELECT
            id,
            license_key,
            scanner_version,
            timestamp,
            files_scanned,
            detections_json,
            processes_json
        FROM scans
        WHERE id = ?
        """,
        (
            scan_id,
        )
    ).fetchone()

    conn.close()

    if row is None:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return {

        "id":
            row["id"],

        "license_key":
            row["license_key"],

        "scanner_version":
            row["scanner_version"],

        "timestamp":
            row["timestamp"],

        "files_scanned":
            row["files_scanned"],

        "detections":
            json.loads(
                row["detections_json"]
                or "[]"
            ),

        "processes":
            json.loads(
                row["processes_json"]
                or "[]"
            )

    }


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return {

        "service":
            "Xyron Security API",

        "status":
            "online",

        "version":
            "3.0"

    }
