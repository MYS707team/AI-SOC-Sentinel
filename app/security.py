from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time
from fastapi import HTTPException, Request
from .store import utcnow, parse_time

ROLES = {"analyst", "approver", "auditor", "admin", "ml_engineer"}


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    key = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
    return f"scrypt${salt}${key.hex()}"


def verify_password(password, encoded):
    try:
        kind, salt, _ = encoded.split("$")
        return kind == "scrypt" and hmac.compare_digest(hash_password(password, salt), encoded)
    except (ValueError, TypeError):
        return False


def clean_note(text):
    # Notes remain in the case audit, but typical account/secret material is minimized.
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[email-redacted]", text)
    text = re.sub(r"(?i)\b(password|token|secret|authorization)\s*[:=]\s*\S+", r"\1=[redacted]", text)
    return re.sub(r"\b(?:\d[ -]?){12,19}\b", "[number-redacted]", text)


class Security:
    def __init__(self, settings, store):
        self.settings, self.store = settings, store
        path = settings.data_dir / "pseudonym.key"
        if not path.exists():
            if store.all("events") or store.all("training_rows"):
                raise ValueError("Existing data requires its original pseudonym.key; restore the key before starting")
            # Exclusive creation avoids replacing an identity key on concurrent startup.
            try:
                with path.open("xb") as stream:
                    stream.write(secrets.token_bytes(32))
                os.chmod(path, 0o600)
            except FileExistsError:
                pass
        self.key = path.read_bytes()
        if len(self.key) != 32:
            raise ValueError("pseudonym.key must contain exactly 32 bytes")
        self.users = {}
        if settings.users_file:
            self.users = json.loads(Path(settings.users_file).read_text(encoding="utf-8-sig"))
            if not self.users or any(v.get("role") not in ROLES or not v.get("password_hash", "").startswith("scrypt$") for v in self.users.values()):
                raise ValueError("Invalid users file; run scripts/create_user.py")
        self.rate_lock = threading.Lock()
        self.attempts = {}
        self.dummy_hash = hash_password(secrets.token_urlsafe(24))

    def pseudonym(self, value):
        return "entity-" + hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()[:24]

    def rate_limit(self, key, limit=10, seconds=60):
        now = time.monotonic()
        with self.rate_lock:
            self.attempts = {k: v for k, v in self.attempts.items() if v[-1] > now - 3600}
            samples = [t for t in self.attempts.get(key, []) if t > now - seconds]
            if len(samples) >= limit:
                raise HTTPException(429, "RATE_LIMITED")
            samples.append(now)
            self.attempts[key] = samples

    def issue_session(self, username, role, response, request):
        token, csrf = secrets.token_urlsafe(40), secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(hours=self.settings.session_hours)).isoformat()
        with self.store.transaction() as conn:
            old = request.cookies.get("soc_session", "")
            conn.execute("DELETE FROM sessions WHERE token_hash=? OR expires_at<?", (hashlib.sha256(old.encode()).hexdigest(), utcnow()))
            conn.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), username, role, csrf, expires))
            self.store.audit(username, "session.started", username, {"role": role, "mode": self.settings.mode}, conn)
        response.set_cookie("soc_session", token, httponly=True, secure=self.settings.mode != "demo", samesite="strict", max_age=self.settings.session_hours * 3600, path="/")
        return {"user": {"username": username, "role": role}, "csrf_token": csrf, "mode": self.settings.mode}

    def authenticate(self, request: Request):
        token = request.cookies.get("soc_session", "")
        with self.store.connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not row or parse_time(row["expires_at"]) <= datetime.now(timezone.utc):
            raise HTTPException(401, "AUTH_REQUIRED")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), row["csrf"]):
                raise HTTPException(403, "CSRF_INVALID")
        return {"username": row["username"], "role": row["role"], "csrf_token": row["csrf"]}

    @staticmethod
    def require(user, *roles):
        if user["role"] not in roles:
            raise HTTPException(403, "ROLE_FORBIDDEN")

    def assert_demo(self, request):
        local = request.client and request.client.host in {"127.0.0.1", "::1", "localhost"}
        if self.settings.mode != "demo" or not (local or self.settings.testing):
            raise HTTPException(403, "DEMO_LOOPBACK_ONLY")
