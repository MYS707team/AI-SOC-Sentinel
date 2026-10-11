from datetime import datetime, timedelta, timezone
import json
import sqlite3
import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app
from app.store import digest, utcnow


@pytest.fixture
def system(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, testing=True, ingest_token="t" * 40))
    with TestClient(app) as client:
        yield app, client


def login(client, role="analyst"):
    response = client.post("/api/auth/demo", json={"role": role})
    assert response.status_code == 200
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return response.json()


def replay(client):
    response = client.post("/api/demo/replay", json={"scenario": "credential_compromise"})
    assert response.status_code == 200
    cases = client.get("/api/state").json()["incidents"]
    return max((i for i in cases if i["asset_id"] == "bank-node-02"), key=lambda i: i["created_at"])


def test_session_csrf_origin_rbac_and_security_headers(system):
    app, client = system
    assert client.get("/api/state").status_code == 401
    result = login(client, "auditor")
    assert client.get("/api/state").status_code == 200
    assert client.post("/api/demo/replay", json={"scenario": "mixed"}).status_code == 403
    assert client.post("/api/auth/logout", json={}, headers={"X-CSRF-Token": "bad"}).status_code == 403
    assert client.post("/api/auth/demo", json={"role": "admin"}, headers={"Origin": "https://evil.example"}).status_code == 403
    response = client.get("/api/state")
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert client.get("/api/export/dataset").status_code == 200
    token = client.cookies.get("soc_session")
    assert token and len(token) > 40
    with app.state.store.connect() as conn:
        stored = conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert token != stored
    assert client.post("/api/auth/logout", json={}).status_code == 200
    assert client.get("/api/state").status_code == 401


def test_ingestion_atomic_idempotent_and_no_raw_identity(system):
    app, client = system
    event = {"id": "collector-example", "source": "identity", "event_type": "login_failed", "event_time": utcnow(),
        "asset_id": "bank-node-02", "entity_id": "person@example.com", "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20"}
    headers = {"Authorization": "Bearer " + "t" * 40}
    assert client.post("/api/ingest/events", json={"events": [event]}).status_code == 401
    r = client.post("/api/ingest/events", json={"events": [event]}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] == 1
    assert client.post("/api/ingest/events", json={"events": [event]}, headers=headers).json()["duplicates"] == 1
    assert "person@example.com" not in json.dumps(app.state.store.get("events", event["id"]))
    conflicting = {**event, "bytes_out": 99}
    earlier = {**event, "id": "must-rollback"}
    assert client.post("/api/ingest/events", json={"events": [earlier, conflicting]}, headers=headers).status_code == 409
    assert app.state.store.get("events", earlier["id"]) is None
    for invalid in [{**event, "raw_password": "NEVER_ECHO_THIS"}, {**event, "bytes_out": -1}, {**event, "event_time": "2026-10-11T10:00:00"}, {**event, "src_ip": "junk"}]:
        response = client.post("/api/ingest/events", json={"events": [invalid]}, headers=headers)
        assert response.status_code == 422
        assert "NEVER_ECHO_THIS" not in response.text
    assert app.state.store.verify_audit()["valid"]


def test_label_review_keeps_uncertain_out_and_snapshots_exact_features(system):
    app, client = system
    login(client, "admin")
    incident = replay(client)
    row_count = len(app.state.store.all("training_rows"))
    response = client.post(f"/api/incidents/{incident['id']}/labels", json={"label": "malicious", "reason": "Analyst observed the ordered chain"})
    label = response.json()
    assert response.status_code == 200
    assert client.post(f"/api/labels/{label['id']}/review", json={"decision": "approve", "reason": "Independent evidence reviewed"}).status_code == 403
    login(client, "approver")
    assert client.post(f"/api/labels/{label['id']}/review", json={"decision": "approve", "reason": "Independent evidence reviewed"}).status_code == 200
    rows = app.state.store.all("training_rows")
    assert len(rows) == row_count + 1
    row = next(r for r in rows if r["event_id"] == label["event_id"])
    assert digest(row["features"]) == label["features_hash"]
    assert row["label"] == 1 and row["created_by"] != row["reviewed_by"]
    assert client.post(f"/api/labels/{label['id']}/review", json={"decision": "approve", "reason": "Independent evidence reviewed"}).status_code == 409
    login(client, "analyst")
    another = replay(client)
    uncertain = client.post(f"/api/incidents/{another['id']}/labels", json={"label": "uncertain", "reason": "Not enough supporting evidence"}).json()
    login(client, "approver")
    assert client.post(f"/api/labels/{uncertain['id']}/review", json={"decision": "approve", "reason": "Independent evidence reviewed"}).status_code == 422
    assert len(app.state.store.all("training_rows")) == row_count + 1


def test_response_policy_two_person_idempotency_verification_and_rollback(system):
    app, client = system
    login(client, "admin")
    assert client.post("/api/policies", json={"kill_switch": False}).status_code == 200
    case = replay(client)
    action = client.post(f"/api/incidents/{case['id']}/actions", json={"kind": "isolate_endpoint", "reason": "Contain a confirmed suspicious chain"}).json()
    path = f"/api/actions/{action['id']}"
    assert client.post(path + "/approve", json={"reason": "Review complete by another operator"}).status_code == 403
    login(client, "approver")
    assert client.post(path + "/approve", json={"reason": "Review complete by another operator"}).status_code == 200
    executed = client.post(path + "/execute", json={}).json()
    assert executed["status"] == "executed"
    repeated = client.post(path + "/execute", json={}).json()
    assert executed["provider_request_id"] == repeated["provider_request_id"]
    assert client.post(path + "/verify", json={}).json()["verification"]["effective"]
    incident = client.get(f"/api/incidents/{case['id']}").json()["incident"]
    assert incident["status"] == "open", "Simulation cannot claim actual containment"
    rolled_back = client.post(path + "/rollback", json={"reason": "Restore simulated endpoint connectivity"}).json()
    assert rolled_back["status"] == "rolled_back" and rolled_back["rollback_verified"]
    assert client.post(path + "/execute", json={}).json()["status"] == "rolled_back"
    critical = next(i for i in app.state.store.all("incidents") if app.state.store.get("assets", i["asset_id"])["criticality"] == "critical")
    login(client, "analyst")
    assert client.post(f"/api/incidents/{critical['id']}/actions", json={"kind": "isolate_endpoint", "reason": "Test critical asset authorization"}).status_code == 403


def test_approval_expiry_and_policy_change_are_rechecked(system):
    app, client = system
    login(client, "analyst")
    case = replay(client)
    action = client.post(f"/api/incidents/{case['id']}/actions", json={"kind": "revoke_sessions", "reason": "Review the compromised identity sessions"}).json()
    login(client, "approver")
    assert client.post(f"/api/actions/{action['id']}/approve", json={"reason": "Independent review of identity evidence"}).status_code == 200
    login(client, "admin")
    client.post("/api/policies", json={"kill_switch": False})
    response = client.post(f"/api/actions/{action['id']}/execute", json={})
    assert response.status_code == 409 and response.json()["detail"] == "POLICY_CHANGED_REPLAN"
    client.post(f"/api/actions/{action['id']}/reject", json={"reason": "Old policy invalidated previous plan"})
    new = client.post(f"/api/incidents/{case['id']}/actions", json={"kind": "revoke_sessions", "reason": "Review the compromised identity sessions"}).json()
    with app.state.store.transaction() as conn:
        a = app.state.store.get("actions", new["id"], conn)
        a["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        a["binding_hash"] = app.state.soc.action_binding(a)
        app.state.store.put("actions", a, conn)
    login(client, "approver")
    r = client.post(f"/api/actions/{new['id']}/approve", json={"reason": "Independent review of identity evidence"})
    assert r.status_code == 409 and r.json()["detail"] == "APPROVAL_EXPIRED"


def test_manual_ml_training_promotion_rollback_and_no_automation(system):
    app, client = system
    login(client, "analyst")
    fingerprint = client.get("/api/state").json()["learning"]["dataset_hash"]
    body = {"dataset_hash": fingerprint, "reviewed": True}
    assert client.post("/api/learning/train", json=body).status_code == 403
    login(client, "ml_engineer")
    assert client.post("/api/learning/train", json={**body, "reviewed": False}).status_code == 422
    assert client.post("/api/learning/train", json={**body, "dataset_hash": "0" * 64}).status_code == 409
    result = client.post("/api/learning/train", json=body)
    assert result.status_code == 200, result.text
    model = result.json()
    assert model["status"] == "challenger" and model["eligible"]
    assert model["production_eligible"] is False
    assert client.get("/api/state").json()["overview"]["model_version"] == "rules-1.0"
    assert client.post("/api/learning/train", json=body).status_code == 409
    assert client.post("/api/learning/policy", json={"enabled": True}).status_code == 404
    login(client, "approver")
    assert client.post(f"/api/models/{model['id']}/promote", json={"reason": "Independently reviewed synthetic-only gates"}).status_code == 200
    assert client.get("/api/state").json()["overview"]["model_version"] == model["version"]
    login(client, "admin")
    assert client.post("/api/models/MODEL-RULES-V1/rollback", json={"reason": "Restore the known baseline rules"}).status_code == 200
    assert client.get("/api/audit/verify").json()["valid"]


def test_audit_changes_are_detected_and_append_only(system):
    app, client = system
    login(client, "auditor")
    assert client.get("/api/audit/verify").json()["valid"]
    with app.state.store.connect() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit SET action='tampered'")
    with app.state.store.connect() as conn:
        conn.execute("DROP TRIGGER audit_no_update")
        conn.execute("UPDATE audit SET details='{}' WHERE seq=1")
    assert client.get("/api/audit/verify").json()["valid"] is False


def test_pilot_has_no_demo_bypass_no_seed_and_requires_secure_configuration(tmp_path):
    from app.security import hash_password
    with pytest.raises(ValueError):
        create_app(Settings(data_dir=tmp_path / "invalid", mode="pilot"))
    users_file = tmp_path / "users.json"
    users_file.write_text(json.dumps({"engineer": {"role": "ml_engineer", "password_hash": hash_password("example-strong-password-123")}}))
    pilot = create_app(Settings(data_dir=tmp_path / "pilot", mode="pilot", origin="https://soc.example.test",
        ingest_token="t" * 40, users_file=str(users_file), testing=True))
    with TestClient(pilot, base_url="https://soc.example.test") as client:
        assert client.post("/api/auth/demo", json={"role": "admin"}).status_code == 403
        response = client.post("/api/auth/login", json={"username": "engineer", "password": "example-strong-password-123"})
        assert response.status_code == 200
        assert "Secure" in response.headers["set-cookie"] and "HttpOnly" in response.headers["set-cookie"]
        assert client.get("/api/state").json()["overview"]["events_total"] == 0
        assert pilot.state.store.all("assets") == []
