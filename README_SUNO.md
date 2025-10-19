# Suno Vulnerable Test Application

Suno is a deliberately vulnerable banking-style web service designed to stress-test the Zevionx CLI agent. It exposes multiple non-SQL injection attack surfaces so you can validate end‑to‑end reconnaissance, exploitation, and reporting workflows.

## Features & Intentional Vulnerabilities

| Endpoint | Description | Vulnerability |
|----------|-------------|---------------|
| `POST /auth/login` | Issues a JWT for the supplied user | JWT verification disabled (role escalation) |
| `GET /dashboard` | Returns account data for the JWT subject | Trusts tampered tokens |
| `POST /api/diagnostics/ping` | “Ping” utility for network checks | Command injection via unsanitised shell execution |
| `GET /api/preview?target=` | Fetch external URL preview | SSRF (weak hostname filter) |
| `GET /files/download?file=` | Download statements | Path traversal to arbitrary files |

The vulnerabilities are intentionally simple to exercise but require the agent to chain reconnaissance, payload creation, and verification steps without relying on SQL injection heuristics.

## Running Suno

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-suno.txt

python -m suno_app.app
```

The application listens on `http://127.0.0.1:5000` by default. Set `SUNO_PORT` to change the port and `SUNO_JWT_SECRET` to customise the JWT signing key (keeping signature verification disabled).

### Example users

| Username   | Password   | Role   |
|------------|------------|--------|
| `alice`    | `alice2024`| `user` |
| `bob`      | `bob2024`  | `analyst` |
| `sunoadmin`| `admin123!`| `admin` |

The `/dashboard` endpoint reveals the role derived from the (tamperable) JWT.

## Pitting Zevionx Against Suno

Point the CLI at `http://127.0.0.1:5000` and ask it to assess the login flow, diagnostics API, or file service. A successful run should:

1. Recon the login endpoint and observe the JWT cookie.
2. Escalate privileges by forging a token (`role: admin`).
3. Trigger command injection in `/api/diagnostics/ping`.
4. Abuse `/api/preview` to perform SSRF (e.g. hit the local metadata service).
5. Leak `documents/account-summary.txt` via directory traversal.

Because the attack paths differ from SQL injection, this target is ideal for exercising the agent’s new planning, evidence aggregation, and reporting logic.
