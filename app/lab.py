"""Authenticated loopback cyber range with real TCP requests and inline denial.

Only this module's ephemeral 127.0.0.1 server can be targeted. The intentionally
vulnerable SQL target uses a fresh in-memory database of three fictional rows;
no OS commands, real credentials, bank connections or external egress exist.
"""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import gzip
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx
from fastapi import HTTPException

from .http_detection import SCHEMA, FEATURE_NAMES, features, rule_reasons, score, validate_artifact
from .http_learning import load_public, train_http
from .security import clean_note
from .store import canonical, digest, new_id, parse_time, utcnow


class LabService:
    def __init__(self, settings, store, security):
        self.settings, self.store, self.security = settings, store, security
        self.lock, self.run_lock, self.train_lock = threading.RLock(), threading.Lock(), threading.Lock()
        self.server = self.thread = self.model = None
        self.sessions = {}
        self.base_path = settings.data_dir / "http" / "public.jsonl"
        if settings.mode == "demo":
            self._bootstrap()

    def _assert_enabled(self):
        if self.settings.mode != "demo":
            raise HTTPException(403, "LAB_DISABLED_IN_PILOT")

    def _bootstrap(self):
        # Ship the trained, non-executable artifact and public numeric features.
        # Never overwrite an operator's existing training corpus or model.
        assets = Path(__file__).resolve().parents[1] / "assets"
        target = self.settings.data_dir / "http"
        target.mkdir(parents=True, exist_ok=True)
        for source, dest in (("http-model.json", "bootstrap-model.json"),
                             ("public.manifest.json", "public.manifest.json"),
                             ("public.jsonl.gz", "public.jsonl")):
            src, dst = assets / source, target / dest
            if src.exists() and not dst.exists():
                data = gzip.decompress(src.read_bytes()) if source.endswith(".gz") else src.read_bytes()
                try:
                    with dst.open("xb") as stream:
                        stream.write(data)
                except FileExistsError:
                    pass
        with self.store.transaction() as conn:
            if not self.store.get("settings", "http_lab", conn):
                self.store.put("settings", {"id": "http_lab", "auto_block": True, "version": 1}, conn)
            if not self.store.get("assets", "lab-http-target", conn):
                self.store.put("assets", {"id": "lab-http-target", "name": "Loopback HTTP range",
                    "criticality": "standard", "type": "lab", "synthetic": True}, conn)
            path = self.settings.data_dir / "http" / "bootstrap-model.json"
            models = self.store.all("http_models", conn)
            if path.exists():
                bundle = json.loads(path.read_text(encoding="utf8"))
                artifact = bundle["artifact"]
                if digest(artifact) != bundle["artifact_hash"]:
                    raise ValueError("HTTP_MODEL_INTEGRITY_FAILED")
                validate_artifact(artifact)
                report = bundle["report"]
                register = not any(m["id"] == artifact["version"] for m in models)
                activate = report["eligible"] and not any(m["status"] == "active" and m["trained_by"] != "local.bootstrap" for m in models)
                item = {"id": artifact["version"], "version": artifact["version"], "status": "active" if activate else "rejected",
                    "artifact_hash": bundle["artifact_hash"], "report": report,
                    "dataset_manifest": bundle["dataset_manifest"], "trained_by": "local.bootstrap",
                    "created_at": utcnow(), "scope": "loopback_lab_only", "production_eligible": False}
                if register:
                    if activate:
                        for old in models:
                            if old["status"] == "active":
                                old["status"] = "retired"
                                self.store.put("http_models", old, conn)
                    self.store.put("http_models", item, conn)
                    self.store.put("http_artifacts", {"id": item["id"], "artifact": artifact}, conn)
                    self.store.audit("local.bootstrap", "http_model.registered", item["id"],
                        {"artifact_hash": item["artifact_hash"], "scope": "loopback_lab_only"}, conn)
            self._reload_model(conn)

    def _reload_model(self, conn=None):
        active = next((m for m in self.store.all("http_models", conn) if m["status"] == "active"), None)
        self.model = None
        if active:
            stored = self.store.get("http_artifacts", active["id"], conn)
            if not stored or digest(stored["artifact"]) != active["artifact_hash"]:
                raise ValueError("HTTP_MODEL_INTEGRITY_FAILED")
            validate_artifact(stored["artifact"])
            self.model = {**active, "artifact": stored["artifact"]}

    def start(self):
        self._assert_enabled()
        with self.lock:
            if self.server:
                return
            lab = self

            class Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.0"

                def setup(self):
                    super().setup()
                    self.connection.settimeout(5)

                def log_message(self, *args):
                    pass  # request paths can contain confidential values

                def do_GET(self):
                    self.handle_request()

                def do_POST(self):
                    self.handle_request()

                def handle_request(self):
                    try:
                        if self.client_address[0] != "127.0.0.1":
                            return self.reply(403, {"error": "LOOPBACK_ONLY"})
                        token = self.headers.get("X-Lab-Session", "")
                        with lab.lock:
                            session = lab.sessions.get(token)
                        if not session or parse_time(session["expires_at"]) <= datetime.now(timezone.utc):
                            return self.reply(403, {"error": "LAB_SESSION_REQUIRED"})
                        expected_host = f"127.0.0.1:{lab.server.server_address[1]}"
                        if self.headers.get("Host") != expected_host or self.headers.get("Transfer-Encoding"):
                            return self.reply(400, {"error": "INVALID_LAB_REQUEST"})
                        size = int(self.headers.get("Content-Length", "0"))
                        if size < 0 or size > 8192 or len(self.path) > 8192:
                            return self.reply(413, {"error": "HTTP_REQUEST_TOO_LARGE"})
                        body = self.rfile.read(size).decode("utf8", errors="replace") if size else ""
                        result, status = lab.handle(self.command, self.path, body, session)
                        return self.reply(status, result)
                    except (ValueError, UnicodeError):
                        return self.reply(400, {"error": "INVALID_LAB_REQUEST"})
                    except Exception:
                        # If detection/audit cannot commit, the target is not run.
                        return self.reply(503, {"error": "LAB_DETECTION_OR_AUDIT_UNAVAILABLE"})

                def reply(self, status, obj):
                    payload = canonical(obj).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
                    self.end_headers()
                    self.wfile.write(payload)

            self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            self.server.daemon_threads = True
            self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .1}, daemon=True)
            self.thread.start()

    def close(self):
        with self.lock:
            server, thread = self.server, self.thread
            self.server = self.thread = None
            self.sessions.clear()
        if server:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def _session(self, group, mode="protect"):
        self.start()
        token = secrets.token_urlsafe(32)
        item = {"group_id": group, "mode": mode, "actor": self.security.pseudonym(token),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()}
        with self.lock:
            expired = [t for t, s in self.sessions.items() if parse_time(s["expires_at"]) <= datetime.now(timezone.utc)]
            for t in expired:
                self.sessions.pop(t, None)
            if len(self.sessions) >= 256:
                raise HTTPException(429, "LAB_SESSION_LIMIT")
            self.sessions[token] = item
        return token

    def send(self, token, path, payload="", method="GET"):
        # No caller-controlled host, port, absolute URL, redirects or proxy env.
        if path not in {"/search", "/echo", "/file", "/login"} or method not in {"GET", "POST"} or len(payload.encode()) > 7000:
            raise HTTPException(422, "INVALID_LAB_REQUEST")
        with self.lock:
            if not self.server or token not in self.sessions:
                raise HTTPException(409, "LAB_SESSION_EXPIRED")
            port = self.server.server_address[1]
        with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
            response = client.request(method, f"http://127.0.0.1:{port}{path}" + ("?" + urlencode({"q": payload}) if method == "GET" else ""),
                headers={"X-Lab-Session": token, "Content-Type": "application/x-www-form-urlencoded"},
                content=urlencode({"q": payload}) if method == "POST" else None)
        result = response.json()
        if response.status_code >= 500 or "event_id" not in result:
            raise HTTPException(503, "LAB_TRANSPORT_OR_DETECTION_FAILED")
        return {**result, "http_status": response.status_code}

    @staticmethod
    def target(path, value):
        """A bounded real SQL injection can change the result in this toy DB."""
        if path == "/search":
            with sqlite3.connect(":memory:") as conn:
                conn.execute("CREATE TABLE products (name TEXT, category TEXT)")
                conn.executemany("INSERT INTO products VALUES (?, ?)", [("demo-book", "books"), ("demo-pen", "office"), ("demo-card", "gifts")])
                conn.commit()
                conn.set_authorizer(lambda op, table, col, db, trigger: sqlite3.SQLITE_OK
                    if op == sqlite3.SQLITE_SELECT or (op == sqlite3.SQLITE_READ and table == "products") else sqlite3.SQLITE_DENY)
                conn.set_progress_handler(lambda: 1, 5000)
                try:
                    # Deliberately vulnerable; only SELECT in fresh in-memory DB.
                    rows = conn.execute("SELECT name FROM products WHERE category = '" + value + "'").fetchall()
                    return 200, {"target_executed": True, "rows_returned": len(rows), "fictional_data_only": True}
                except sqlite3.Error:
                    return 400, {"target_executed": True, "query_rejected": True, "fictional_data_only": True}
        if path == "/login":
            return (200 if value == "demo-correct" else 401), {"target_executed": True, "fictional_identity_only": True}
        # XSS is never executed by a browser; traversal never touches the disk.
        return 200, {"target_executed": True, "accepted_bytes": len(value.encode()), "fictional_data_only": True}

    def handle(self, method, target, body, session):
        began = time.perf_counter()
        f = features(method, target, body)
        rules = rule_reasons(f)
        with self.lock:
            model = self.model
        model_score = score(f, model["artifact"]) if model else None
        model_alert = bool(model and model_score >= model["artifact"]["alert_threshold"])
        model_block = bool(model and model["report"]["auto_block_eligible"] and model_score >= model["artifact"]["block_threshold"])
        parsed = urlsplit(target)
        values = parse_qs(parsed.query if method == "GET" else body, keep_blank_values=True)
        value = values.get("q", [""])[0]
        identifier, at = new_id("HTTP"), utcnow()
        with self.store.transaction() as conn:
            policy = self.store.get("settings", "http_lab", conn)
            block = self.store.get("http_blocks", session["actor"], conn)
            actor_block = bool(block and block["enabled"] and parse_time(block["expires_at"]) > datetime.now(timezone.utc))
            if parsed.path == "/login":
                failures = sum(e["entity_id"] == session["actor"] and e.get("response_status") == 401 and
                    (parse_time(at) - parse_time(e["event_time"])).total_seconds() < 300 for e in self.store.all("http_events", conn))
                if failures >= 3:
                    rules.append("AUTH_FAILURE_BURST")
            alert = bool(rules or model_alert or not model or actor_block)
            blocked_by = "analyst" if actor_block else "model" if model_block else "rules" if rules else None
            blocked = actor_block or (session["mode"] == "protect" and policy["auto_block"] and bool(model_block or rules))
            if not blocked:
                blocked_by = None
            reasons = rules + (["HTTP_MODEL_ANOMALY"] if model_alert else []) + (["HTTP_MODEL_UNAVAILABLE"] if not model else [])
            event = {"id": identifier, "event_type": "http_request", "source": "network", "feature_schema": SCHEMA,
                "event_time": at, "received_at": at, "decision_time": at, "group_id": session["group_id"],
                "entity_id": session["actor"], "asset_id": "lab-http-target", "method": method,
                "route": parsed.path if parsed.path in {"/search", "/echo", "/file", "/login"} else "unknown",
                "request_hash": self.security.pseudonym(method + target + body), "features": f, "features_hash": digest(f),
                "model_score": model_score, "model_version": model["version"] if model else "http-rules-fallback",
                "model_alert": model_alert, "rule_alert": bool(rules), "alert": alert,
                "reason_codes": reasons, "blocked": blocked, "blocked_by": blocked_by,
                "score": round(max((model_score or 0) * 100, 90 if rules else 0), 2),
                "severity": "high" if alert else "low", "mode": session["mode"], "policy_version": policy["version"],
                "source_kind": "local_lab_capture", "synthetic": True, "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1",
                "bytes_out": len(target.encode()) + len(body.encode()), "outcome": "pending",
                "training_eligible": parsed.path != "/login", "raw_payload_stored": False}
            if alert:
                case_id = "INC-HTTP-" + digest(session["actor"])[:16].upper()
                case = self.store.get("incidents", case_id, conn)
                if not case:
                    case = {"id": case_id, "detector": "http", "title_code": "http_security_signal", "asset_id": "lab-http-target",
                        "entity_id": session["actor"], "status": "open", "owner": None, "severity": "high", "score": 0,
                        "created_at": at, "event_ids": [], "reason_codes": [], "mitre": ["T1190"], "synthetic": True}
                case["event_ids"] = (case["event_ids"] + [identifier])[-200:]
                case["reason_codes"] = sorted(set(case["reason_codes"] + reasons))
                if event["score"] >= case["score"]:
                    case.update(score=event["score"], decision_event_id=identifier, features=f, model_version=event["model_version"])
                if case["status"] == "closed":
                    case["status"] = "open"
                case.update(updated_at=at, last_event_time=at, delivery="soc_inbox", escalation_status="pending",
                    response_summary="request_blocked" if blocked else "analyst_review_required")
                event["incident_id"] = case_id
                self.store.put("incidents", case, conn)
            self.store.put("http_events", event, conn)
            self.store.audit("lab.gateway", "http.decided", identifier,
                {"model_version": event["model_version"], "features_hash": event["features_hash"], "blocked": blocked,
                 "blocked_by": blocked_by, "incident_id": event.get("incident_id"), "target_executed": False}, conn)
        status, outcome = (403, {"target_executed": False, "rows_returned": 0}) if blocked else self.target(parsed.path, value)
        event.update(response_status=status, target_executed=outcome["target_executed"], outcome="blocked" if blocked else "delivered",
            latency_ms=round((time.perf_counter() - began) * 1000, 3), target_result=outcome)
        with self.store.transaction() as conn:
            self.store.put("http_events", event, conn)
            self.store.audit("lab.gateway", "http.outcome", identifier,
                {"http_status": status, "target_executed": outcome["target_executed"], "blocked_by": blocked_by}, conn)
        return {"event_id": identifier, "incident_id": event.get("incident_id"), "blocked": blocked,
            "blocked_by": blocked_by, "model_score": model_score, "model_alert": model_alert, "rule_alert": bool(rules),
            "model_version": event["model_version"], "latency_ms": event["latency_ms"], **outcome}, status

    def custom(self, path, payload, method, actor):
        token = self._session(new_id("JUDGE"))
        result = self.send(token, path, payload, method)
        with self.store.transaction() as conn:
            self.store.audit(actor, "lab.custom_request", result["event_id"], {"scope": "loopback_lab_only"}, conn)
        return result

    def run(self, actor):
        self._assert_enabled()
        if not self.run_lock.acquire(blocking=False):
            raise HTTPException(409, "LAB_RUN_ALREADY_RUNNING")
        run = {"id": new_id("LABRUN"), "created_at": utcnow(), "actor": actor, "status": "running"}
        try:
            with self.store.transaction() as conn:
                self.store.put("http_lab_runs", run, conn)
            fixtures = [
                ("normal_search", "/search", "books", 0),
                ("normal_text", "/echo", "Bank xizmatlari haqida oddiy savol", 0),
                ("normal_punctuation", "/echo", "O'Reilly & Sons: invoice 2026-10", 0),
                ("sql_boolean", "/search", "' OR 1=1 -- ", 1),
                ("sql_union", "/search", "' UNION SELECT name FROM products -- ", 1),
                ("sql_obfuscated", "/search", "'/**/OR/**/1=1-- ", 1),
                ("xss_marker", "/echo", '<svg onload=alert("lab")>', 1),
                ("traversal_marker", "/file", "../../etc/passwd", 1),
                ("encoded_xss", "/echo", "%3Cscript%3Ealert(1)%3C/script%3E", 1),
            ]
            results = []
            observe = self._session(run["id"] + "-control", "observe")
            for name, path, payload, truth in fixtures:
                control = self.send(observe, path, payload)
                # Independent identity per attack: previous blocks cannot inflate
                # detection of a later, different payload.
                protect = self._session(run["id"] + "-" + name)
                defended = self.send(protect, path, payload)
                results.append({"scenario": name, "expected_anomalous": bool(truth), "control": control, "protected": defended})
            brute = self._session(run["id"] + "-auth")
            auth = [self.send(brute, "/login", "wrong-demo-" + str(i), "POST") for i in range(5)]
            results.append({"scenario": "auth_failure_burst", "expected_anomalous": True, "attempts": auth, "protected": auth[-1]})
            attack = [r for r in results if r["expected_anomalous"]]
            benign = [r for r in results if not r["expected_anomalous"]]
            run.update(status="completed", completed_at=utcnow(), results=results,
                summary={"attacks": len(attack), "blocked": sum(r["protected"]["blocked"] for r in attack),
                    "escalated": sum(bool(r["protected"].get("incident_id")) and not r["protected"]["blocked"] for r in attack),
                    "missed": sum(not r["protected"].get("incident_id") for r in attack),
                    "benign": len(benign), "benign_blocked": sum(r["protected"]["blocked"] for r in benign),
                    "model_only_alerts": sum(r["protected"]["model_alert"] and not r["protected"]["rule_alert"] for r in results),
                    "actual_tcp_requests": len(fixtures) * 2 + len(auth)},
                scope="loopback_lab_only", labels_added_to_training=0)
            with self.store.transaction() as conn:
                self.store.put("http_lab_runs", run, conn)
                self.store.audit(actor, "lab.run_completed", run["id"], run["summary"], conn)
            return run
        except Exception:
            with self.store.transaction() as conn:
                run.update(status="failed", completed_at=utcnow(), error_code="LAB_RUN_FAILED")
                self.store.put("http_lab_runs", run, conn)
                self.store.audit(actor, "lab.run_failed", run["id"], {"error_code": "LAB_RUN_FAILED"}, conn)
            raise
        finally:
            self.run_lock.release()

    def _required_event(self, identifier, conn=None):
        event = self.store.get("http_events", identifier, conn)
        if not event:
            raise HTTPException(404, "NOT_FOUND")
        return event

    def feedback(self, identifier, label, disposition, reason, user):
        self._assert_enabled()
        with self.lock:
            sessions = dict(self.sessions)
        with self.store.transaction() as conn:
            event = self._required_event(identifier, conn)
            if any(l.get("event_id") == identifier and l["status"] == "pending" for l in self.store.all("labels", conn)):
                raise HTTPException(409, "LABEL_REVIEW_PENDING")
            if label not in {"malicious", "benign", "uncertain"} or disposition not in {"block", "release", "escalate", "monitor"}:
                raise HTTPException(422, "INVALID_INPUT")
            item = {"id": new_id("HLBL"), "detector": "http", "feature_schema": SCHEMA, "event_id": identifier,
                "incident_id": event.get("incident_id"), "label": label, "status": "pending", "disposition": disposition,
                "reason": clean_note(reason), "created_by": user["username"], "created_at": utcnow(),
                "reviewed_by": None, "features_hash": event["features_hash"], "synthetic": True}
            if disposition in {"block", "release"}:
                token = next((t for t, s in sessions.items() if s["actor"] == event["entity_id"] and parse_time(s["expires_at"]) > datetime.now(timezone.utc)), None)
                if not token:
                    raise HTTPException(409, "LAB_SESSION_EXPIRED")
                action_id = new_id("HACT")
                self.store.put("http_blocks", {"id": event["entity_id"], "enabled": disposition == "block",
                    "expires_at": sessions[token]["expires_at"], "action_id": action_id}, conn)
                action = {"id": action_id, "event_id": identifier, "actor": user["username"], "kind": disposition,
                    "scope": "one_lab_session", "status": "applied_verification_pending", "created_at": utcnow(), "reason": clean_note(reason)}
                self.store.put("http_actions", action, conn)
                item["action_id"] = action_id
            self.store.put("labels", item, conn)
            if event.get("incident_id"):
                case = self.store.get("incidents", event["incident_id"], conn)
                case.update(owner=user["username"], status="investigating", escalation_status="acknowledged",
                    analyst_disposition=disposition, updated_at=utcnow())
                self.store.put("incidents", case, conn)
            self.store.audit(user["username"], "http.feedback_proposed", item["id"],
                {"event_id": identifier, "label": label, "disposition": disposition, "action_id": item.get("action_id")}, conn)
        if item.get("action_id"):
            try:
                probe = self.send(token, "/echo", "lab-verification")
                effective = (probe["blocked_by"] == "analyst" and probe["http_status"] == 403 and not probe["target_executed"]) if disposition == "block" else probe["blocked_by"] != "analyst"
                action.update(status="verified" if effective else "verification_failed", effective=effective, probe_event_id=probe["event_id"])
            except Exception:
                action.update(status="verification_failed", effective=False)
            with self.store.transaction() as conn:
                self.store.put("http_actions", action, conn)
                self.store.audit(user["username"], "http.action_verified", action["id"],
                    {"effective": action["effective"], "kind": disposition, "scope": "one_lab_session"}, conn)
        return item

    def review(self, identifier, decision, reason, user):
        with self.store.transaction() as conn:
            item = self.store.get("labels", identifier, conn)
            if not item or item.get("detector") != "http":
                raise HTTPException(404, "NOT_FOUND")
            if item["created_by"] == user["username"]:
                raise HTTPException(403, "SELF_APPROVAL_FORBIDDEN")
            if item["status"] != "pending":
                raise HTTPException(409, "LABEL_ALREADY_REVIEWED")
            if item["label"] == "uncertain" and decision == "approve":
                raise HTTPException(422, "UNCERTAIN_NOT_TRAINABLE")
            event = self._required_event(item["event_id"], conn)
            if item["features_hash"] != digest(event["features"]):
                raise HTTPException(409, "FEATURE_SNAPSHOT_CHANGED")
            item.update(status="approved" if decision == "approve" else "rejected", reviewed_by=user["username"],
                reviewed_at=utcnow(), review_reason=clean_note(reason))
            if decision == "approve":
                for old in self.store.all("labels", conn):
                    if old.get("event_id") == event["id"] and old["status"] == "approved":
                        old["status"] = "superseded"
                        self.store.put("labels", old, conn)
                if event["training_eligible"]:
                    action = self.store.get("http_actions", item.get("action_id", ""), conn)
                    row = {"id": event["id"], "event_id": event["id"], "features": event["features"],
                        "features_hash": item["features_hash"], "label": int(item["label"] == "malicious"),
                        "group_id": event["group_id"], "event_time": event["event_time"], "observed_at": event["received_at"],
                        "label_available_at": item["reviewed_at"], "feature_schema": SCHEMA, "label_id": item["id"],
                        "created_by": item["created_by"], "reviewed_by": user["username"], "review_status": "approved",
                        "provenance": "independently-reviewed-local-http", "source_kind": "local_lab_capture", "synthetic": True,
                        "analyst_disposition": item["disposition"], "action_outcome": action,
                        "decision_model": event["model_version"], "decision_blocked": event["blocked"],
                        "response_status": event["response_status"], "target_executed": event["target_executed"]}
                    self.store.put("http_feedback", row, conn)
                    # Revisions invalidate candidates based on the old snapshot.
                    for model in self.store.all("http_models", conn):
                        if event["id"] in model.get("feedback_ids", []):
                            model["data_review_required"] = True
                            self.store.put("http_models", model, conn)
            self.store.put("labels", item, conn)
            self.store.audit(user["username"], "http.feedback_reviewed", identifier,
                {"decision": decision, "training_eligible": event["training_eligible"], "features_hash": item["features_hash"]}, conn)
            return item

    def dataset_hash(self, conn=None):
        manifest = self.base_path.with_suffix(".manifest.json")
        source = json.loads(manifest.read_text(encoding="utf8"))["dataset_sha256"] if manifest.exists() else None
        feedback = sorted(self.store.all("http_feedback", conn), key=lambda r: r["id"])
        return digest({"public": source, "feedback": feedback})

    def train(self, user, expected_hash):
        self._assert_enabled()
        if not self.train_lock.acquire(blocking=False):
            raise HTTPException(409, "TRAINING_ALREADY_RUNNING")
        run_id = new_id("HTRAIN")
        try:
            with self.store.transaction() as conn:
                if expected_hash != self.dataset_hash(conn):
                    raise HTTPException(409, "DATASET_CHANGED_REVIEW_AGAIN")
                if any(m.get("dataset_hash") == expected_hash for m in self.store.all("http_models", conn)):
                    raise HTTPException(409, "DATASET_UNCHANGED")
                feedback = self.store.all("http_feedback", conn)
                parent = self.model["version"] if self.model else None
                self.store.put("http_training_runs", {"id": run_id, "status": "running", "actor": user["username"], "created_at": utcnow()}, conn)
                self.store.audit(user["username"], "http.training_started", run_id, {"dataset_hash": expected_hash}, conn)
            base, manifest = load_public(self.base_path)
            artifact, report = train_http(base, feedback, parent)
            item = {"id": new_id("HMODEL"), "version": artifact["version"], "artifact_hash": digest(artifact),
                "report": report, "dataset_manifest": manifest, "status": "challenger", "trained_by": user["username"],
                "created_at": utcnow(), "dataset_hash": expected_hash, "parent_version": parent,
                "feedback_ids": [r["id"] for r in feedback], "scope": "loopback_lab_only", "production_eligible": False}
            with self.store.transaction() as conn:
                item["data_review_required"] = expected_hash != self.dataset_hash(conn)
                self.store.put("http_models", item, conn)
                self.store.put("http_artifacts", {"id": item["id"], "artifact": artifact}, conn)
                self.store.put("http_training_runs", {"id": run_id, "status": "completed", "model_id": item["id"], "actor": user["username"], "completed_at": utcnow()}, conn)
                self.store.audit(user["username"], "http.training_completed", run_id,
                    {"model_id": item["id"], "feedback": report["feedback"], "eligible": report["eligible"]}, conn)
            return item
        except Exception:
            with self.store.transaction() as conn:
                if self.store.get("http_training_runs", run_id, conn):
                    self.store.put("http_training_runs", {"id": run_id, "status": "failed", "error_code": "HTTP_TRAINING_FAILED", "completed_at": utcnow()}, conn)
                    self.store.audit(user["username"], "http.training_failed", run_id, {"error_code": "HTTP_TRAINING_FAILED"}, conn)
            raise
        finally:
            self.train_lock.release()

    def promote(self, identifier, user, reason, rollback=False):
        self._assert_enabled()
        with self.lock, self.store.transaction() as conn:
            model = self.store.get("http_models", identifier, conn)
            if not model:
                raise HTTPException(404, "NOT_FOUND")
            if model.get("data_review_required"):
                raise HTTPException(409, "TRAINING_LABELS_CHANGED")
            if model.get("dataset_manifest", {}).get("feature_schema") != SCHEMA:
                raise HTTPException(409, "HTTP_MODEL_SCHEMA_INVALID")
            if rollback:
                if model["status"] != "retired":
                    raise HTTPException(409, "ROLLBACK_REQUIRES_PREVIOUS_CHAMPION")
            else:
                if model["trained_by"] == user["username"]:
                    raise HTTPException(403, "SELF_APPROVAL_FORBIDDEN")
                if model["status"] != "challenger" or not model["report"]["eligible"]:
                    raise HTTPException(409, "MODEL_GATES_FAILED")
                if model["dataset_hash"] != self.dataset_hash(conn):
                    raise HTTPException(409, "DATASET_CHANGED_REVIEW_AGAIN")
                if model.get("parent_version") != (self.model["version"] if self.model else None):
                    raise HTTPException(409, "CHAMPION_CHANGED_REEVALUATE")
            stored = self.store.get("http_artifacts", model["id"], conn)
            if digest(stored["artifact"]) != model["artifact_hash"]:
                raise HTTPException(409, "MODEL_INTEGRITY_FAILED")
            validate_artifact(stored["artifact"])
            for old in self.store.all("http_models", conn):
                if old["status"] == "active":
                    old["status"] = "retired"
                    self.store.put("http_models", old, conn)
            model.update(status="active", approved_by=user["username"], approved_at=utcnow())
            self.store.put("http_models", model, conn)
            self.store.audit(user["username"], "http.model_rollback" if rollback else "http.model_promoted", model["id"],
                {"reason": clean_note(reason), "scope": "loopback_lab_only"}, conn)
        with self.lock:
            self._reload_model()
        return model

    def state(self):
        if self.settings.mode != "demo":
            return {"enabled": False}
        with self.store.transaction() as conn:
            events = self.store.all("http_events", conn)
            labels = [l for l in self.store.all("labels", conn) if l.get("detector") == "http"]
            return {"enabled": True, "running": self.server is not None, "scope": "loopback_lab_only",
                "storage": "ephemeral" if self.settings.hosted_demo else "persistent_local",
                "model_ready": self.model is not None, "model_version": self.model["version"] if self.model else None,
                "events_total": len(events), "blocked": sum(e["blocked"] for e in events),
                "escalated": sum(e["alert"] and not e["blocked"] for e in events),
                "pending_labels": sum(l["status"] == "pending" for l in labels),
                "feedback_rows": len(self.store.all("http_feedback", conn)), "dataset_hash": self.dataset_hash(conn),
                "policy": self.store.get("settings", "http_lab", conn),
                "events": list(reversed(events))[:100], "labels": list(reversed(labels))[:100],
                "models": [{**m, "compatible": m.get("dataset_manifest", {}).get("feature_schema") == SCHEMA}
                    for m in reversed(self.store.all("http_models", conn))],
                "runs": list(reversed(self.store.all("http_lab_runs", conn)))[:10],
                "actions": list(reversed(self.store.all("http_actions", conn)))[:50],
                "training_runs": list(reversed(self.store.all("http_training_runs", conn)))[:10]}
