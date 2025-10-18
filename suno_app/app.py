# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import datetime
import os
import subprocess
from pathlib import Path
from typing import Dict, Optional

import jwt
import requests
from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    request,
    send_file,
)

BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = BASE_DIR / "documents"
FILES_DIR.mkdir(parents=True, exist_ok=True)

USERS: Dict[str, Dict[str, str]] = {
    "alice": {"password": "alice2024", "role": "user"},
    "bob": {"password": "bob2024", "role": "analyst"},
    "sunoadmin": {"password": "admin123!", "role": "admin"},
}

JWT_SECRET = os.environ.get("SUNO_JWT_SECRET", "suno-dev-secret")

app = Flask(__name__)


def _issue_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=4),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _decode_token(token: str) -> Optional[Dict[str, str]]:
    """
    Vulnerable helper: signature verification disabled to "support third-party tokens".
    Allows arbitrary role escalation by tampering with the JWT payload.
    """
    try:
        return jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
            },
        )
    except jwt.PyJWTError:
        return None


def _get_session():
    token = request.cookies.get("suno_session") or request.headers.get("X-Suno-Session")
    if not token:
        return None
    return _decode_token(token)


@app.route("/")
def index():
    return jsonify(
        {
            "app": "Suno Vulnerable Banking Portal",
            "endpoints": {
                "POST /auth/login": "Obtain session cookie",
                "GET /dashboard": "View account dashboard (requires session)",
                "POST /api/diagnostics/ping": "Network diagnostics (command injection)",
                "GET /api/preview": "Fetch remote URL content (SSRF)",
                "GET /files/download": "Download statements (path traversal)",
            },
        }
    )


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    user = USERS.get(username)
    if not user or user["password"] != password:
        abort(401, description="Invalid credentials")
    token = _issue_token(username, user["role"])
    response = make_response(
        jsonify(
            {
                "message": "login successful",
                "token": token,
                "role": user["role"],
            }
        )
    )
    # HttpOnly session cookie containing JWT (subject to tampering).
    response.set_cookie(
        "suno_session",
        token,
        httponly=True,
        secure=False,
        samesite="Lax",
    )
    return response


@app.get("/dashboard")
def dashboard():
    session = _get_session()
    if not session:
        abort(401, description="Missing or invalid session")
    role = session.get("role", "user")
    sensitive = role == "admin"
    return jsonify(
        {
            "message": f"Welcome back, {session.get('sub', 'guest')}!",
            "role": role,
            "admin_area": sensitive,
            "accounts": [
                {"id": "CHK-001", "balance": 15432.77},
                {"id": "SAV-214", "balance": 82000.11},
            ],
            "alerts": [
                "Enable MFA for additional protection.",
                "Review last month's statements.",
            ],
        }
    )


@app.post("/api/diagnostics/ping")
def diagnostics_ping():
    """
    Vulnerable command injection:
    Executes user-supplied host value inside shell without sanitization.
    """
    data = request.get_json(silent=True) or request.form
    host = data.get("host") or request.args.get("host")
    if not host:
        abort(400, description="Host parameter required")

    command = f"ping -c 2 {host}"
    try:
        output = subprocess.check_output(
            command,
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=5,
        )
        return jsonify({"command": command, "output": output.decode()})
    except subprocess.CalledProcessError as exc:
        return jsonify(
            {"command": command, "error": exc.output.decode(), "returncode": exc.returncode}
        ), 500
    except subprocess.TimeoutExpired:
        abort(504, description="Ping timed out")


@app.get("/api/preview")
def preview():
    """
    Vulnerable SSRF:
    Naive 'localhost' substring block can be bypassed (e.g., 127.0.0.1, decimal, DNS rebinding).
    """
    target = request.args.get("target")
    if not target:
        abort(400, description="target parameter required")
    lowered = target.lower()
    if "localhost" in lowered or "169.254." in lowered:
        abort(403, description="Target host blocked by policy")
    try:
        resp = requests.get(target, timeout=4)
    except requests.RequestException as exc:
        abort(502, description=f"Upstream error: {exc}")
    return jsonify(
        {
            "target": target,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body_preview": resp.text[:500],
        }
    )


@app.get("/files/download")
def download():
    """
    Vulnerable path traversal:
    Directly concatenates user input, allowing ../../ to access arbitrary files.
    """
    filename = request.args.get("file")
    if not filename:
        abort(400, description="file parameter required")
    requested_path = (FILES_DIR / filename).resolve()
    # Intentional bug: trust resolve() but still allow access outside FILES_DIR.
    if not requested_path.exists():
        abort(404, description="File not found")
    return send_file(requested_path)


def create_app() -> Flask:
    return app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("SUNO_PORT", "5000")), debug=True)
