from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import secrets
import sqlite3
import json
from datetime import datetime

app = FastAPI(title="Xyron API")

DB = "xyron.db"
ADMIN_KEY = "XYRON_ADMIN_KEY"

sessions = set()


def get_db():
    return sqlite3.connect(DB)


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
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            status TEXT NOT NULL,
            detections INTEGER NOT NULL DEFAULT 0,
            results TEXT NOT NULL,
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


class ScanReport(BaseModel):
    license_key: str | None = None
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

    if token not in sessions:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized"
        )


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
    sessions.add(token)

    return {
        "token": token
    }


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


@app.post("/license/use")
def use_license(data: LicenseRequest):
    old_key = data.license_key.strip()

    conn = get_db()

    row = conn.execute(
        """
        SELECT active
        FROM licenses
        WHERE license_key = ?
        """,
        (old_key,)
    ).fetchone()

    if not row or row[0] != 1:
        conn.close()

        raise HTTPException(
            status_code=401,
            detail="Invalid or inactive license"
        )

    new_key = generate_license()

    conn.execute(
        """
        UPDATE licenses
        SET active = 0
        WHERE license_key = ?
        """,
        (old_key,)
    )

    conn.execute(
        """
        INSERT INTO licenses
        (license_key, active, created_at)
        VALUES (?, 1, ?)
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
        "new_key": new_key
    }


@app.post("/license/check")
def check_license(data: LicenseRequest):
    conn = get_db()

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
        "valid": bool(row and row[0] == 1)
    }


@app.post("/scan/report")
def scan_report(data: ScanReport):
    conn = get_db()

    conn.execute(
        """
        INSERT INTO scans
        (license_key, status, detections, results, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            data.license_key,
            data.status,
            data.detections,
            json.dumps(data.results),
            datetime.now().isoformat()
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

    conn = get_db()

    rows = conn.execute(
        """
        SELECT
            id,
            license_key,
            status,
            detections,
            results,
            created_at
        FROM scans
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    scans = []

    for row in rows:
        try:
            results = json.loads(row[4])
        except Exception:
            results = []

        scans.append({
            "id": row[0],
            "license_key": row[1],
            "status": row[2],
            "detections": row[3],
            "results": results,
            "created_at": row[5]
        })

    return {
        "scans": scans
    }


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>XYRON ADMIN</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #030208;
    color: #f7f2ff;
    font-family: Arial, sans-serif;
}

body:before {
    content: "";
    position: fixed;
    width: 500px;
    height: 500px;
    background: #241047;
    filter: blur(130px);
    opacity: .45;
    top: -180px;
    left: -150px;
    pointer-events: none;
}

header {
    padding: 28px 7%;
    border-bottom: 1px solid #25163d;
    background: rgba(3,2,8,.75);
}

h1 {
    margin: 0;
    font-size: 32px;
    letter-spacing: 2px;
}

.subtitle {
    margin-top: 5px;
    color: #bd8cff;
    font-size: 11px;
    letter-spacing: 3px;
}

.container {
    max-width: 1150px;
    margin: auto;
    padding: 35px 20px;
}

.login {
    max-width: 400px;
    margin: 80px auto;
    padding: 35px;
    background: #0b0712;
    border: 1px solid #211330;
    border-radius: 12px;
}

.login h2 {
    margin-top: 0;
}

input {
    width: 100%;
    padding: 14px;
    margin-top: 15px;
    background: #030208;
    border: 1px solid #2c174d;
    color: white;
    border-radius: 7px;
    outline: none;
}

button {
    margin-top: 15px;
    padding: 11px 20px;
    border: 0;
    border-radius: 7px;
    background: #8b4dff;
    color: white;
    font-weight: bold;
    cursor: pointer;
}

button:hover {
    background: #a66fff;
}

.topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
}

.scan {
    background: #0b0712;
    border: 1px solid #1d1229;
    margin-top: 15px;
    padding: 20px;
    border-radius: 10px;
}

.scan:hover {
    border-color: #58358b;
}

.clean {
    color: #63dc9a;
}

.review {
    color: #e9c46a;
}

.high {
    color: #ef7777;
}

.result {
    margin-top: 12px;
    padding: 14px;
    background: #05030a;
    border: 1px solid #191020;
    border-radius: 7px;
    font-family: Consolas, monospace;
    white-space: pre-wrap;
}

.hidden {
    display: none;
}

#error {
    color: #ef7777;
    margin-top: 12px;
}

#licenseBox {
    margin-top: 20px;
    padding: 15px;
    background: #0b0712;
    border: 1px solid #25163d;
    border-radius: 8px;
}

</style>
</head>

<body>

<header>
    <h1>XYRON ADMIN</h1>
    <div class="subtitle">
        SECURITY SCAN MANAGEMENT
    </div>
</header>

<div class="container">

    <div id="loginBox" class="login">

        <h2>Admin Login</h2>

        <input
            id="adminKey"
            type="password"
            placeholder="Admin key"
        >

        <button onclick="login()">
            LOGIN
        </button>

        <div id="error"></div>

    </div>


    <div id="dashboard" class="hidden">

        <div class="topbar">

            <div>
                <h2>SCAN RESULTS</h2>
            </div>

            <div>

                <button onclick="createLicense()">
                    CREATE LICENSE
                </button>

                <button onclick="loadScans()">
                    REFRESH
                </button>

            </div>

        </div>

        <div id="licenseBox"></div>

        <div id="scans"></div>

    </div>

</div>


<script>

let token =
    localStorage.getItem("xyron_token");


if (token) {
    showDashboard();
}


async function login() {

    const key =
        document.getElementById(
            "adminKey"
        ).value;

    const error =
        document.getElementById(
            "error"
        );

    error.textContent = "";

    try {

        const response =
            await fetch(
                "/admin/login",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        admin_key: key
                    })
                }
            );

        if (!response.ok) {

            error.textContent =
                "Invalid admin key.";

            return;
        }

        const data =
            await response.json();

        token = data.token;

        localStorage.setItem(
            "xyron_token",
            token
        );

        showDashboard();

    } catch (error) {

        error.textContent =
            "Cannot connect to server.";
    }
}


function showDashboard() {

    document
        .getElementById("loginBox")
        .classList
        .add("hidden");

    document
        .getElementById("dashboard")
        .classList
        .remove("hidden");

    loadScans();
}


async function createLicense() {

    try {

        const response =
            await fetch(
                "/license/create",
                {
                    method: "POST",
                    headers: {
                        "Authorization":
                            "Bearer " + token
                    }
                }
            );

        if (!response.ok) {

            alert(
                "Could not create license."
            );

            return;
        }

        const data =
            await response.json();

        const box =
            document.getElementById(
                "licenseBox"
            );

        box.innerHTML =
            "<b>NEW LICENSE:</b><br><br>"
            + escapeHtml(
                data.license_key
            );

    } catch (error) {

        alert(
            "Server connection failed."
        );
    }
}


async function loadScans() {

    const scansBox =
        document.getElementById(
            "scans"
        );

    scansBox.innerHTML =
        "<p>Loading...</p>";

    try {

        const response =
            await fetch(
                "/admin/scans",
                {
                    headers: {
                        "Authorization":
                            "Bearer " + token
                    }
                }
            );

        if (response.status === 401) {

            localStorage.removeItem(
                "xyron_token"
            );

            location.reload();

            return;
        }

        const data =
            await response.json();

        scansBox.innerHTML = "";

        if (!data.scans.length) {

            scansBox.innerHTML =
                "<p>No scans yet.</p>";

            return;
        }

        for (
            const scan of data.scans
        ) {

            const box =
                document.createElement(
                    "div"
                );

            box.className = "scan";

            let statusClass =
                String(
                    scan.status
                ).toLowerCase();

            let results = "";

            for (
                const item
                of scan.results
            ) {

                results +=
                    "<div class='result'>";

                results +=
                    "NAME: "
                    + escapeHtml(
                        item.name
                    )
                    + "\\n";

                results +=
                    "TYPE: "
                    + escapeHtml(
                        item.type
                    )
                    + "\\n";

                results +=
                    "RISK: "
                    + escapeHtml(
                        item.risk
                    )
                    + "\\n";

                results +=
                    "SCORE: "
                    + escapeHtml(
                        item.score
                    )
                    + "\\n";

                results +=
                    "SHA256: "
                    + escapeHtml(
                        item.sha256
                    )
                    + "\\n";

                if (item.evidence) {

                    results +=
                        "EVIDENCE:\\n";

                    for (
                        const evidence
                        of item.evidence
                    ) {

                        results +=
                            "- "
                            + escapeHtml(
                                evidence
                            )
                            + "\\n";
                    }
                }

                results +=
                    "</div>";
            }

            box.innerHTML =
                "<b>SCAN #"
                + escapeHtml(
                    scan.id
                )
                + "</b><br>"
                + "<span class='"
                + statusClass
                + "'>"
                + escapeHtml(
                    scan.status
                )
                + "</span>"
                + "<br><br>"
                + "DATE: "
                + escapeHtml(
                    scan.created_at
                )
                + "<br>"
                + "LICENSE: "
                + escapeHtml(
                    scan.license_key ||
                    "Unknown"
                )
                + "<br>"
                + "DETECTIONS: "
                + escapeHtml(
                    scan.detections
                )
                + results;

            scansBox.appendChild(
                box
            );
        }

    } catch (error) {

        scansBox.innerHTML =
            "<p>Server connection failed.</p>";
    }
}


function escapeHtml(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    const div =
        document.createElement(
            "div"
        );

    div.textContent =
        String(value);

    return div.innerHTML;
}

</script>

</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000
    )
