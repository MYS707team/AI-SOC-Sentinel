"""Transactions bind state changes and audit records. SQLite is for a single-node pilot."""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import uuid


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class Store:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        with self.connect() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS records (
                    kind TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
                    PRIMARY KEY(kind,id));
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
                    time TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
                    target TEXT NOT NULL, details TEXT NOT NULL,
                    prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
                    BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
                    BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END;
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, username TEXT NOT NULL,
                    role TEXT NOT NULL, csrf TEXT NOT NULL, expires_at TEXT NOT NULL);
            """)

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15, factory=ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def transaction(self):
        with self.lock:
            conn = self.connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.close()

    def all(self, kind, conn=None):
        if conn is None:
            with self.connect() as connection:
                return self.all(kind, connection)
        return [json.loads(r[0]) for r in conn.execute("SELECT body FROM records WHERE kind=? ORDER BY rowid", (kind,))]

    def get(self, kind, identifier, conn=None):
        if conn is None:
            with self.connect() as connection:
                return self.get(kind, identifier, connection)
        row = conn.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, identifier)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, kind, obj, conn):
        conn.execute("INSERT INTO records(kind,id,body) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body", (kind, obj["id"], canonical(obj)))

    def audit(self, actor, action, target, details, conn):
        last = conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        entry = {"id": new_id("AUD"), "time": utcnow(), "actor": actor, "action": action,
                 "target": target, "details": details, "prev_hash": last[0] if last else "0" * 64}
        entry["hash"] = digest(entry)
        conn.execute("INSERT INTO audit(id,time,actor,action,target,details,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
                     tuple(canonical(entry[k]) if k == "details" else entry[k] for k in ("id", "time", "actor", "action", "target", "details", "prev_hash", "hash")))
        self.put("settings", {"id": "audit_head", "hash": entry["hash"]}, conn)
        return entry

    def audit_entries(self, conn=None):
        if conn is None:
            with self.connect() as connection:
                return self.audit_entries(connection)
        entries = []
        for row in conn.execute("SELECT * FROM audit ORDER BY seq"):
            item = dict(row)
            item.pop("seq")
            item["details"] = json.loads(item["details"])
            entries.append(item)
        return entries

    def verify_audit(self, conn=None):
        if conn is None:
            with self.transaction() as connection:
                return self.verify_audit(connection)
        previous = "0" * 64
        entries = self.audit_entries(conn)
        for i, entry in enumerate(entries):
            checksum = entry.pop("hash")
            if entry["prev_hash"] != previous or digest(entry) != checksum:
                return {"valid": False, "checked": i, "head": previous, "broken_at": entry["id"]}
            previous = checksum
        head = self.get("settings", "audit_head", conn)
        return {"valid": (head["hash"] if head else "0" * 64) == previous, "checked": len(entries), "head": previous,
                "guarantee": "tamper-evidence; independent external anchoring required against database administrators"}

