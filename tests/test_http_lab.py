"""Real socket, enforcement, feedback provenance and retraining regressions."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
from urllib.parse import urlencode

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings, ROOT
from app.http_detection import features, score, validate_artifact, MODEL_FEATURE_NAMES
from app.http_learning import feature_group, load_public, partition, train_http
from app.main import create_app
from app.store import digest
from tests.test_api import login


@pytest.fixture
def lab_system(tmp_path):
    bundle = ROOT / ".runtime" / "http" / "bootstrap-model.json"
    if not bundle.exists():
        bundle = ROOT / "assets" / "http-model.json"
    if not bundle.exists():
        pytest.skip("Run scripts/train_http.py --download to enable trained-model integration tests")
    (tmp_path / "http").mkdir()
    shutil.copy2(bundle, tmp_path / "http" / "bootstrap-model.json")
    app = create_app(Settings(data_dir=tmp_path, testing=True, auto_seed=False))
    with TestClient(app) as client:
        login(client, "admin")
        yield app, client


def test_model_is_application_independent_and_features_do_not_contain_identity():
    one = features("GET", "http://first.example/catalog?customer=ordinary+words")
    two = features("POST", "/different/banking/path", "name=ordinary+words")
    assert {k: one[k] for k in MODEL_FEATURE_NAMES} == {k: two[k] for k in MODEL_FEATURE_NAMES}
    assert feature_group(one) == feature_group(two)
    assert all(type(v) in (int, float) for v in one.values())
    assert "ordinary" not in json.dumps(one)


def test_real_attack_control_protection_and_no_automatic_labels(lab_system):
    app, client = lab_system
    response = client.post("/api/lab/run", json={})
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["summary"]["actual_tcp_requests"] == 23
    assert run["summary"]["missed"] == 0
    assert run["summary"]["benign_blocked"] == 0
    sql = next(r for r in run["results"] if r["scenario"] == "sql_boolean")
    assert sql["control"]["target_executed"] and sql["control"]["rows_returned"] == 3
    assert sql["protected"]["http_status"] == 403 and not sql["protected"]["target_executed"]
    obfuscated = next(r for r in run["results"] if r["scenario"] == "sql_obfuscated")["protected"]
    assert obfuscated["model_alert"] and not obfuscated["rule_alert"]
    assert obfuscated["blocked_by"] == "model"
    assert not app.state.store.all("http_feedback")
    assert not app.state.store.all("labels")
    case = client.get("/api/incidents/" + obfuscated["incident_id"]).json()
    assert case["incident"]["delivery"] == "soc_inbox"
    assert any(e["id"] == obfuscated["event_id"] for e in case["events"])
    assert app.state.store.verify_audit()["valid"]


def test_observe_escalates_and_analyst_block_is_verified_by_real_probe(lab_system):
    app, client = lab_system
    assert client.post("/api/lab/policy", json={"auto_block": False}).status_code == 200
    sample = client.post("/api/lab/request", json={"path": "/search", "payload": "' OR 7=7 -- ", "method": "GET"}).json()
    assert not sample["blocked"] and sample["target_executed"] and sample["incident_id"]
    login(client, "analyst")
    response = client.post(f"/api/lab/events/{sample['event_id']}/feedback", json={
        "label": "malicious", "disposition": "block", "reason": "Verified SQL control returned extra fictional rows"})
    assert response.status_code == 200, response.text
    label = response.json()
    action = app.state.store.get("http_actions", label["action_id"])
    assert action["status"] == "verified" and action["effective"]
    probe = app.state.store.get("http_events", action["probe_event_id"])
    assert probe["response_status"] == 403 and not probe["target_executed"] and probe["blocked_by"] == "analyst"
    assert not app.state.store.all("http_feedback")
    # Same person is forbidden even when they have the reviewer role.
    with app.state.store.transaction() as conn:
        item = app.state.store.get("labels", label["id"], conn)
        item["created_by"] = "demo.approver"
        app.state.store.put("labels", item, conn)
    login(client, "approver")
    review = {"decision": "approve", "reason": "Independent review of captured request features"}
    assert client.post(f"/api/labels/{label['id']}/review", json=review).status_code == 403
    login(client, "admin")
    assert client.post(f"/api/labels/{label['id']}/review", json=review).status_code == 200
    rows = app.state.store.all("http_feedback")
    assert len(rows) == 1 and rows[0]["label"] == 1
    assert rows[0]["features_hash"] == label["features_hash"]
    assert rows[0]["action_outcome"]["effective"]
    assert rows[0]["created_by"] != rows[0]["reviewed_by"]
    assert "OR 7=7" not in json.dumps(rows)
    assert client.post(f"/api/labels/{label['id']}/review", json=review).status_code == 409
    release = client.post(f"/api/lab/events/{sample['event_id']}/feedback", json={
        "label": "malicious", "disposition": "release", "reason": "Completed containment test; release this lab session"}).json()
    assert app.state.store.get("http_actions", release["action_id"])["effective"]


def test_benign_and_uncertain_feedback_and_schema_separation(lab_system):
    app, client = lab_system
    normal = client.post("/api/lab/request", json={"payload": "ordinary bank question"}).json()
    login(client, "analyst")
    label = client.post(f"/api/lab/events/{normal['event_id']}/feedback", json={
        "label": "uncertain", "disposition": "escalate", "reason": "Need more contextual evidence before deciding"}).json()
    login(client, "approver")
    assert client.post(f"/api/labels/{label['id']}/review", json={"decision": "approve", "reason": "Checked independent evidence"}).status_code == 422
    assert not app.state.store.all("http_feedback")
    assert client.post(f"/api/labels/{label['id']}/review", json={"decision": "reject", "reason": "No trainable ground truth established"}).status_code == 200
    login(client, "analyst")
    label = client.post(f"/api/lab/events/{normal['event_id']}/feedback", json={
        "label": "benign", "disposition": "monitor", "reason": "Known normal request reviewed against target outcome"}).json()
    login(client, "approver")
    assert client.post(f"/api/labels/{label['id']}/review", json={"decision": "approve", "reason": "Independent benign review completed"}).status_code == 200
    assert app.state.store.all("http_feedback")[0]["label"] == 0
    assert not app.state.store.all("training_rows"), "HTTP features must never pollute the context model"
    assert app.state.store.verify_audit()["valid"]


def test_boundary_no_external_target_no_unauthenticated_or_cross_origin_attack(lab_system):
    app, client = lab_system
    assert client.post("/api/lab/request", json={"path": "https://example.com", "payload": "x"}).status_code == 422
    assert client.post("/api/lab/request", json={"path": "/search", "target": "example.com"}).status_code == 422
    assert client.post("/api/lab/run", json={}, headers={"Origin": "https://example.com"}).status_code == 403
    assert client.post("/api/lab/run", json={}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    login(client, "auditor")
    assert client.post("/api/lab/run", json={}).status_code == 403
    app.state.lab.start()
    port = app.state.lab.server.server_address[1]
    assert app.state.lab.server.server_address[0] == "127.0.0.1"
    with httpx.Client(trust_env=False) as remote:
        assert remote.get(f"http://127.0.0.1:{port}/search?q=books").status_code == 403


def test_audit_failure_cannot_execute_target(lab_system, monkeypatch):
    app, client = lab_system
    called = []
    monkeypatch.setattr(app.state.lab, "target", lambda *a: called.append(a))
    def fail(*a, **kw):
        raise RuntimeError("disk unavailable")
    monkeypatch.setattr(app.state.store, "audit", fail)
    response = client.post("/api/lab/request", json={"payload": "ordinary question"})
    assert response.status_code == 503
    assert not called


def test_artifact_tamper_and_cycle_fail_closed(lab_system):
    app, _ = lab_system
    artifact = deepcopy(app.state.lab.model["artifact"])
    artifact["trees"][0]["left"][0] = 0
    with pytest.raises(ValueError):
        validate_artifact(artifact)
    artifact = deepcopy(app.state.lab.model["artifact"])
    artifact["block_threshold"] = float("nan")
    with pytest.raises(ValueError):
        validate_artifact(artifact)
    artifact = app.state.lab.model["artifact"]
    with pytest.raises(ValueError):
        score({"bad": 1}, artifact)


def test_feedback_train_promote_revision_and_restart(lab_system):
    app, client = lab_system
    source = ROOT / ".runtime" / "http" / "public.jsonl"
    for file in (source, source.with_suffix(".manifest.json")):
        shutil.copy2(file, app.state.settings.data_dir / "http" / file.name)
    name = next("reviewed-run-" + str(i) for i in range(100) if partition("reviewed-run-" + str(i)) == "train")
    token = app.state.lab._session(name)
    result = app.state.lab.send(token, "/echo", "Reviewed harmless request for local bank service 99193")
    login(client, "analyst")
    label = client.post(f"/api/lab/events/{result['event_id']}/feedback", json={
        "label": "benign", "disposition": "monitor", "reason": "Known harmless local operation with verified outcome"}).json()
    login(client, "approver")
    assert client.post(f"/api/labels/{label['id']}/review", json={"decision": "approve", "reason": "Independent local operation evidence checked"}).status_code == 200
    login(client, "ml_engineer")
    fingerprint = client.get("/api/lab/state").json()["dataset_hash"]
    assert client.post("/api/lab/train", json={"dataset_hash": "0" * 64, "reviewed": True}).status_code == 409
    response = client.post("/api/lab/train", json={"dataset_hash": fingerprint, "reviewed": True})
    assert response.status_code == 200, response.text
    model = response.json()
    assert model["status"] == "challenger" and model["report"]["feedback"]["train"] == 1
    login(client, "approver")
    response = client.post(f"/api/lab/models/{model['id']}/promote", json={"reason": "Independently reviewed local laboratory gates"})
    assert response.status_code == 200, response.text
    assert app.state.lab.model["version"] == model["version"]
    app.state.lab.close()
    restarted = create_app(app.state.settings)
    assert restarted.state.lab.model["version"] == model["version"]
    assert len(restarted.state.store.all("http_feedback")) == 1
    login(client, "analyst")
    correction = client.post(f"/api/lab/events/{result['event_id']}/feedback", json={
        "label": "malicious", "disposition": "monitor", "reason": "New evidence requires correction of prior reviewed label"}).json()
    login(client, "approver")
    assert client.post(f"/api/labels/{correction['id']}/review", json={"decision": "approve", "reason": "Independent review of changed evidence"}).status_code == 200
    assert app.state.store.get("http_models", model["id"])["data_review_required"]
    assert len(app.state.store.all("http_feedback")) == 1
    assert app.state.store.verify_audit()["valid"]
