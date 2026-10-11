from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import logging
import os
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.staticfiles import StaticFiles
from .config import ROOT, Settings
from .detection import FEATURE_NAMES
from .schemas import (ActionRequest, DemoLogin, IngestBatch, IncidentStatus, LabelRequest,
                      Login, PolicyRequest, Reason, ReplayRequest, ReviewRequest, TrainRequest,
                      LabRequest, LabFeedback, LabPolicy)
from .lab import LabService
from .http_detection import FEATURE_NAMES as HTTP_FEATURE_NAMES, SCHEMA as HTTP_SCHEMA
from .security import Security, clean_note, verify_password
from .service import SOCService
from .store import Store, canonical, digest, new_id, parse_time, utcnow

logger = logging.getLogger("soc")


def create_app(settings=None):
    settings = settings or Settings()
    settings.validate()
    store = Store(settings.data_dir / "soc.db")
    security = Security(settings, store)
    soc = SOCService(settings, store, security)
    lab = LabService(settings, store, security)

    @asynccontextmanager
    async def lifespan(app):
        soc.seed()
        try:
            yield
        finally:
            lab.close()

    app = FastAPI(title="Sentinel AI-SOC", version="1.0.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.security, app.state.soc, app.state.settings = store, security, soc, settings
    app.state.lab = lab
    hosts = ["127.0.0.1", "localhost", "[::1]", urlparse(settings.origin).hostname]
    if settings.hosted_demo:
        hosts.extend(os.environ.get(name, "") for name in
                     ("VERCEL_URL", "VERCEL_BRANCH_URL", "VERCEL_PROJECT_PRODUCTION_URL"))
    if settings.testing:
        hosts.append("testserver")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(set(filter(None, hosts))))

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        request_id = new_id("REQ")
        response = None
        # Same-origin requests only; no permissive CORS or trusted proxy auth headers.
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            allowed_origins = {settings.origin, str(request.base_url).rstrip("/")}
            if request.headers.get("sec-fetch-site") == "cross-site" or (origin and origin not in allowed_origins):
                response = JSONResponse({"detail": "ORIGIN_FORBIDDEN"}, status_code=403)
            if not response:
                content_type = request.headers.get("content-type", "").split(";")[0]
                if content_type != "application/json":
                    response = JSONResponse({"detail": "JSON_REQUIRED"}, status_code=415)
            if not response:
                body, size = [], 0
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > settings.max_body_bytes:
                        response = JSONResponse({"detail": "PAYLOAD_TOO_LARGE"}, status_code=413)
                        break
                    body.append(chunk)
                if not response:
                    request._body = b"".join(body)
        if response is None:
            try:
                response = await call_next(request)
            except Exception:
                logger.exception("Request failed (%s)", request_id)
                response = JSONResponse({"detail": "INTERNAL_ERROR", "request_id": request_id}, status_code=500)
        response.headers.update({
            "X-Request-ID": request_id, "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            "Cache-Control": "no-store",
        })
        if settings.mode != "demo":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request, exc):
        # Never echo raw request values (could contain credentials/PII).
        fields = [".".join(map(str, e["loc"])) for e in exc.errors()]
        return JSONResponse({"detail": "INVALID_INPUT", "fields": fields}, status_code=422)

    def user(request, *roles):
        identity = security.authenticate(request)
        if roles:
            security.require(identity, *roles)
        return identity

    @app.get("/healthz")
    def health():
        with store.connect() as conn:
            conn.execute("SELECT 1").fetchone()
        return {"status": "ok", "mode": settings.mode, "version": "1.0.0", "live_execution": False,
                "storage": "ephemeral" if settings.hosted_demo else "persistent_local"}

    @app.get("/api/auth/me")
    def me(request: Request):
        identity = user(request)
        return {"user": {"username": identity["username"], "role": identity["role"]},
                "csrf_token": identity["csrf_token"], "mode": settings.mode}

    @app.post("/api/auth/demo")
    def demo_login(body: DemoLogin, request: Request, response: Response):
        security.assert_demo(request)
        security.rate_limit(f"demo:{request.client.host}", 40)
        return security.issue_session(f"demo.{body.role}", body.role, response, request)

    @app.post("/api/auth/login")
    def login(body: Login, request: Request, response: Response):
        security.rate_limit(f"login:{request.client.host}", 10, 300)
        entry = security.users.get(body.username)
        valid = verify_password(body.password, entry["password_hash"] if entry else security.dummy_hash)
        if not valid or not entry:
            with store.transaction() as conn:
                store.audit("anonymous", "session.denied", "login", {"account_hash": security.pseudonym(body.username)}, conn)
            raise HTTPException(401, "INVALID_CREDENTIALS")
        return security.issue_session(body.username, entry["role"], response, request)

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response):
        identity = user(request)
        with store.transaction() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(request.cookies.get("soc_session", "").encode()).hexdigest(),))
            store.audit(identity["username"], "session.ended", identity["username"], {}, conn)
        response.delete_cookie("soc_session", path="/")
        return {"ok": True}

    @app.get("/api/state")
    def state(request: Request):
        user(request)
        # A consistent snapshot prevents UI totals disagreeing during ingestion.
        with store.transaction() as conn:
            events = store.all("events", conn)
            incidents = store.all("incidents", conn)
            labels = store.all("labels", conn)
            models = store.all("models", conn)
            training = store.all("training_rows", conn)
            champion = soc.champion(conn)
            now = datetime.now(timezone.utc)
            trend = []
            for offset in range(11, -1, -1):
                start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=offset)
                stop = start + timedelta(hours=1)
                trend.append({"hour": start.isoformat().replace("+00:00", "Z"),
                    "events": sum(start <= parse_time(e["received_at"]) < stop for e in events),
                    "alerts": sum(start <= parse_time(i["created_at"]) < stop for i in incidents)})
            names = {"identity": "Identity / Windows Security", "endpoint": "Endpoint / Wazuh", "network": "Network / Zeek", "core_banking": "Core banking / application audit"}
            connectors = []
            for source, name in names.items():
                samples = [e for e in events if e["source"] == source]
                last = max((e["received_at"] for e in samples), default=None)
                connectors.append({"id": source, "name": name, "category": source, "status": "simulated" if settings.mode == "demo" else "healthy" if last and (now - parse_time(last)).total_seconds() < 300 else "stale" if last else "disconnected",
                    "last_seen": last, "event_count": len(samples), "mode": "synthetic" if settings.mode == "demo" else "normalized_ingest"})
            latest_model = next((m for m in reversed(models) if m.get("dataset_hash")), None)
            drift = {"status": "insufficient_data", "method": "population_stability_index", "reference_count": 0, "recent_count": 0}
            if len(events) >= 80:
                from .learning import drift_summary
                ordered = sorted(events, key=lambda e: e["received_at"])
                drift = drift_summary(ordered[:-40], ordered[-40:])
            return {"meta": {"mode": settings.mode, "synthetic": settings.mode == "demo", "tenant": "Meridian Bank · Sandbox" if settings.mode == "demo" else "Bank pilot",
                    "now": utcnow(), "version": "1.0.0", "readiness": "local-validation", "events_returned": min(len(events), 200), "events_total": len(events)},
                "overview": {"events_total": len(events), "incidents_open": sum(i["status"] != "closed" for i in incidents),
                    "critical_incidents": sum(i["severity"] == "critical" and i["status"] != "closed" for i in incidents),
                    "review_queue": sum(l["status"] == "pending" for l in labels), "model_version": champion["version"], "alert_trend": trend},
                "events": sorted(events, key=lambda e: (e["received_at"], e["id"]), reverse=True)[:200],
                "incidents": sorted(incidents, key=lambda i: (i["status"] != "closed", i["score"], i["created_at"]), reverse=True),
                "models": [soc.public_model(m) for m in reversed(models)], "labels": list(reversed(labels)),
                "learning": {"labels_total": len(labels), "confirmed_labels": sum(l["status"] == "approved" for l in labels),
                    "pending_review": sum(l["status"] == "pending" for l in labels), "dataset_count": len(training), "drift": drift,
                    "feature_names": list(FEATURE_NAMES), "latest_manifest": latest_model.get("split_manifest") if latest_model else None,
                    "runs": list(reversed(store.all("runs", conn))), "manual_retraining_only": True,
                    "dataset_hash": digest(sorted(training, key=lambda r: r["event_id"])),
                    "readiness": {"rows": len(training), "minimum_rows": 600, "positive": sum(r["label"] for r in training),
                        "negative": sum(1-r["label"] for r in training), "minimum_each_class": 50,
                        "ready_for_review": len(training) >= 600 and min(sum(r["label"] for r in training), sum(1-r["label"] for r in training)) >= 50,
                        "synthetic_rows": sum(r["synthetic"] for r in training), "threshold_kind": "provisional_review_threshold_not_bank_acceptance"},
                    "sampling": {"strategy": "uncertainty + severity + source diversity", "daily_budget": 30}},
                "actions": list(reversed(store.all("actions", conn))), "audit": list(reversed(store.audit_entries(conn)))[0:200],
                "connectors": connectors, "assets": store.all("assets", conn), "policies": soc.policy(conn)}

    @app.get("/api/events")
    def list_events(request: Request, q: str = "", source: str = "", severity: str = "", offset: int = 0, limit: int = 100):
        user(request)
        if not 1 <= limit <= 200 or offset < 0 or len(q) > 100:
            raise HTTPException(422, "INVALID_INPUT")
        rows = sorted(store.all("events"), key=lambda e: e["received_at"], reverse=True)
        rows = [e for e in rows if (not source or e["source"] == source) and (not severity or e["severity"] == severity)
            and (not q or q.lower() in " ".join(str(e[k]) for k in ("id", "event_type", "asset_id", "entity_id", "source")).lower())]
        return {"items": rows[offset:offset + limit], "total": len(rows), "offset": offset, "limit": limit}

    @app.get("/api/dataset")
    def inspect_dataset(request: Request, offset: int = 0, limit: int = 30):
        user(request)
        if not 1 <= limit <= 100 or offset < 0:
            raise HTTPException(422, "INVALID_INPUT")
        rows = sorted(store.all("training_rows"), key=lambda r: r["label_available_at"], reverse=True)
        return {"items": rows[offset:offset + limit], "total": len(rows), "offset": offset, "limit": limit}

    @app.get("/api/incidents/{identifier}")
    def incident_detail(identifier: str, request: Request):
        user(request)
        with store.transaction() as conn:
            incident = soc.required("incidents", identifier, conn)
            return {"incident": incident, "events": sorted([e for e in store.all("events", conn) + store.all("http_events", conn) if e["id"] in incident["event_ids"]], key=lambda e: e["event_time"]),
                "labels": [l for l in store.all("labels", conn) if l["incident_id"] == identifier],
                "actions": [a for a in store.all("actions", conn) if a["incident_id"] == identifier]}

    @app.post("/api/incidents/{identifier}/status")
    def incident_status(identifier: str, body: IncidentStatus, request: Request):
        identity = user(request, "analyst", "approver", "admin")
        with store.transaction() as conn:
            incident = soc.required("incidents", identifier, conn)
            transitions = {"open": {"investigating"}, "investigating": {"open", "contained", "closed"}, "contained": {"investigating", "closed"}, "closed": {"investigating"}}
            if body.status != incident["status"] and body.status not in transitions[incident["status"]]:
                raise HTTPException(409, "INVALID_INCIDENT_TRANSITION")
            if body.status == "closed" and not any(l["incident_id"] == identifier and l["status"] == "approved" for l in store.all("labels", conn)):
                raise HTTPException(409, "REVIEWED_LABEL_REQUIRED")
            incident.update(status=body.status, updated_at=utcnow(), owner=body.owner if body.owner is not None else identity["username"])
            store.put("incidents", incident, conn)
            store.audit(identity["username"], "incident.updated", identifier, {"status": body.status, "owner": incident["owner"]}, conn)
            return incident

    @app.post("/api/incidents/{identifier}/labels")
    def submit_label(identifier: str, body: LabelRequest, request: Request):
        identity = user(request, "analyst", "approver", "admin")
        incident = soc.required("incidents", identifier)
        if incident.get("detector") == "http":
            return lab.feedback(incident["decision_event_id"], body.label, "monitor", body.reason, identity)
        return soc.submit_label(identifier, body.label, body.reason, identity)

    @app.post("/api/labels/{identifier}/review")
    def review_label(identifier: str, body: ReviewRequest, request: Request):
        identity = user(request, "approver", "admin")
        if soc.required("labels", identifier).get("detector") == "http":
            return lab.review(identifier, body.decision, body.reason, identity)
        return soc.review_label(identifier, body.decision, body.reason, identity)

    @app.post("/api/learning/train")
    def train(body: TrainRequest, request: Request):
        identity = user(request, "ml_engineer", "admin")
        security.rate_limit("train", 4, 60)
        return soc.train(identity["username"], body.dataset_hash)

    @app.post("/api/models/{identifier}/promote")
    def promote(identifier: str, body: Reason, request: Request):
        return soc.promote(identifier, body.reason, user(request, "approver", "admin"))

    @app.post("/api/models/{identifier}/rollback")
    def rollback_model(identifier: str, body: Reason, request: Request):
        return soc.promote(identifier, body.reason, user(request, "admin"), rollback=True)

    @app.post("/api/demo/replay")
    def replay(body: ReplayRequest, request: Request):
        identity = user(request, "analyst", "admin")
        security.assert_demo(request)
        security.rate_limit("replay", 20, 60)
        return soc.replay(body.scenario, identity["username"])

    @app.post("/api/incidents/{identifier}/actions")
    def propose_action(identifier: str, body: ActionRequest, request: Request):
        return soc.propose_action(identifier, body.kind, body.reason, user(request, "analyst", "admin"))

    @app.post("/api/actions/{identifier}/approve")
    def approve_action(identifier: str, body: Reason, request: Request):
        return soc.transition_action(identifier, "approve", user(request, "approver", "admin"), body.reason)

    @app.post("/api/actions/{identifier}/reject")
    def reject_action(identifier: str, body: Reason, request: Request):
        return soc.transition_action(identifier, "reject", user(request, "approver", "admin"), body.reason)

    @app.post("/api/actions/{identifier}/execute")
    def execute_action(identifier: str, request: Request):
        return soc.transition_action(identifier, "execute", user(request, "analyst", "approver", "admin"))

    @app.post("/api/actions/{identifier}/verify")
    def verify_action(identifier: str, request: Request):
        return soc.transition_action(identifier, "verify", user(request, "analyst", "approver", "admin"))

    @app.post("/api/actions/{identifier}/rollback")
    def rollback_action(identifier: str, body: Reason, request: Request):
        return soc.transition_action(identifier, "rollback", user(request, "approver", "admin"), body.reason)

    @app.post("/api/policies")
    def update_policy(body: PolicyRequest, request: Request):
        identity = user(request, "admin")
        with store.transaction() as conn:
            policy = soc.policy(conn)
            if policy["kill_switch"] != body.kill_switch:
                policy.update(kill_switch=body.kill_switch, version=policy["version"] + 1)
                store.put("settings", policy, conn)
                store.audit(identity["username"], "policy.updated", "response", {"version": policy["version"], "kill_switch": body.kill_switch}, conn)
            return policy

    @app.get("/api/audit/verify")
    def verify_audit(request: Request):
        user(request)
        return store.verify_audit()

    @app.get("/api/export/{kind}")
    def export(kind: str, request: Request):
        identity = user(request, "auditor", "admin", "ml_engineer")
        if kind not in {"dataset", "evidence"}:
            raise HTTPException(404, "NOT_FOUND")
        with store.transaction() as conn:
            if kind == "dataset":
                rows = store.all("training_rows", conn)
                allowed = {"event_id", "features", "label", "event_time", "observed_at", "label_available_at", "entity_id", "synthetic", "provenance", "label_id"}
                rows = [{k: v for k, v in r.items() if k in allowed} for r in rows]
                data = {"schema": "soc-dataset-v1", "rows": rows, "feature_names": list(FEATURE_NAMES),
                    "content_hash": digest(rows), "created_at": utcnow(), "identifiers": "HMAC pseudonyms; NOT anonymized",
                    "synthetic_rows": sum(r["synthetic"] for r in rows), "source": "local SOC"}
            else:
                models = [soc.public_model(m) for m in store.all("models", conn)]
                data = {"schema": "soc-evidence-v1", "created_at": utcnow(), "mode": settings.mode,
                    "models": models, "runs": store.all("runs", conn), "audit": store.audit_entries(conn),
                    "audit_verification": store.verify_audit(conn), "policy": soc.policy(conn),
                    "limitations": ["synthetic metrics do not establish bank accuracy", "no live response adapters", "local audit requires external WORM anchoring", "interactive repeated holdout is development evidence"]}
            store.audit(identity["username"], "data.exported", kind, {"content_hash": digest(data)}, conn)
        return Response(canonical(data), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="ai-soc-{kind}.json"'})

    @app.post("/api/ingest/events")
    def ingest(body: IngestBatch, request: Request):
        token = request.headers.get("authorization", "")
        if not settings.ingest_token or not hmac.compare_digest(token, "Bearer " + settings.ingest_token):
            raise HTTPException(401, "COLLECTOR_AUTH_REQUIRED")
        if settings.mode == "demo" and not settings.testing:
            raise HTTPException(403, "PILOT_INGEST_REQUIRED")
        security.rate_limit(f"ingest:{request.client.host}", 120, 60)
        now = datetime.now(timezone.utc)
        rows = [event.model_dump() for event in body.events]
        for row in rows:
            at = parse_time(row["event_time"])
            if at > now + timedelta(seconds=60) or at < now - timedelta(days=30):
                raise HTTPException(422, "EVENT_TIME_OUT_OF_RANGE")
        try:
            return soc.ingest(rows, "collector.normalized")
        except HTTPException as exc:
            with store.transaction() as conn:
                store.audit("collector.normalized", "telemetry.rejected", "ingest", {"code": exc.detail,
                    "batch_hash": digest(rows), "count": len(rows), "raw_payload_stored": False}, conn)
            raise

    @app.get("/api/openapi.json")
    def openapi(request: Request):
        user(request)
        return app.openapi()

    @app.get("/api/lab/state")
    def lab_state(request: Request):
        user(request)
        return lab.state()

    @app.post("/api/lab/run")
    def lab_run(request: Request):
        identity = user(request, "analyst", "admin")
        security.assert_demo(request)
        security.rate_limit("lab.run", 10, 60)
        return lab.run(identity["username"])

    @app.post("/api/lab/request")
    def lab_request(body: LabRequest, request: Request):
        identity = user(request, "analyst", "admin")
        security.assert_demo(request)
        security.rate_limit("lab.request", 60, 60)
        return lab.custom(body.path, body.payload, body.method, identity["username"])

    @app.post("/api/lab/events/{identifier}/feedback")
    def lab_feedback(identifier: str, body: LabFeedback, request: Request):
        identity = user(request, "analyst", "approver", "admin")
        security.assert_demo(request)
        return lab.feedback(identifier, body.label, body.disposition, body.reason, identity)

    @app.post("/api/lab/policy")
    def lab_policy(body: LabPolicy, request: Request):
        identity = user(request, "admin")
        security.assert_demo(request)
        with store.transaction() as conn:
            policy = store.get("settings", "http_lab", conn)
            policy.update(auto_block=body.auto_block, version=policy["version"] + 1)
            store.put("settings", policy, conn)
            store.audit(identity["username"], "lab.policy_updated", "loopback-lab", policy, conn)
        return policy

    @app.post("/api/lab/train")
    def lab_train(body: TrainRequest, request: Request):
        identity = user(request, "ml_engineer", "admin")
        security.assert_demo(request)
        return lab.train(identity, body.dataset_hash)

    @app.post("/api/lab/models/{identifier}/promote")
    def lab_promote(identifier: str, body: Reason, request: Request):
        identity = user(request, "approver", "admin")
        security.assert_demo(request)
        return lab.promote(identifier, identity, body.reason)

    @app.post("/api/lab/models/{identifier}/rollback")
    def lab_rollback(identifier: str, body: Reason, request: Request):
        identity = user(request, "admin")
        security.assert_demo(request)
        return lab.promote(identifier, identity, body.reason, rollback=True)

    @app.get("/api/lab/dataset")
    def lab_dataset(request: Request, offset: int = 0, limit: int = 30):
        user(request)
        if offset < 0 or not 1 <= limit <= 100:
            raise HTTPException(422, "INVALID_INPUT")
        rows = list(reversed(store.all("http_feedback")))
        return {"feature_schema": HTTP_SCHEMA, "total": len(rows), "items": rows[offset:offset + limit],
                "dataset_hash": lab.dataset_hash(), "feature_names": list(HTTP_FEATURE_NAMES)}

    @app.get("/api/lab/export")
    def lab_export(request: Request):
        identity = user(request, "auditor", "ml_engineer", "admin")
        with store.transaction() as conn:
            rows = store.all("http_feedback", conn)
            result = {"schema": "soc-http-feedback-v1", "rows": rows, "content_hash": digest(rows),
                "dataset_hash": lab.dataset_hash(conn), "created_at": utcnow(), "source": "reviewed_local_lab",
                "raw_payloads_included": False, "models": store.all("http_models", conn),
                "runs": store.all("http_lab_runs", conn), "actions": store.all("http_actions", conn)}
            store.audit(identity["username"], "http.dataset_exported", "http_feedback", {"hash": result["content_hash"]}, conn)
        return Response(canonical(result), media_type="application/json", headers={"Content-Disposition": 'attachment; filename="ai-soc-http-feedback.json"'})

    @app.get("/api/review-queue")
    def review_queue(request: Request):
        user(request)
        reviewed = {l["incident_id"] for l in store.all("labels") if l["status"] in {"approved", "pending"}}
        cases = [i for i in store.all("incidents") if i["id"] not in reviewed and i["status"] != "closed"]
        # Budget one case per identity with uncertainty + severity, no repeated prompts.
        cases.sort(key=lambda i: (abs(i["score"] - 50), -i["score"], i["created_at"]))
        selected, entities = [], set()
        for incident in cases:
            if incident["entity_id"] not in entities:
                entities.add(incident["entity_id"])
                selected.append(incident)
            if len(selected) >= 30:
                break
        return {"items": selected, "budget": 30, "strategy": "uncertainty_then_severity_one_per_entity",
            "limitation": "heuristic review prioritization, not calibrated model uncertainty"}

    @app.get("/")
    def index():
        return FileResponse(ROOT / "web" / "index.html")

    app.mount("/web", StaticFiles(directory=str(ROOT / "web")), name="web")
    return app


app = create_app()
