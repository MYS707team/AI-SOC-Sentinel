from .test_api import login, replay, system


def test_corrected_label_flags_affected_candidate_and_blocks_stale_promotion(system):
    app, client = system
    login(client, "analyst")
    case = replay(client)
    label = client.post(f"/api/incidents/{case['id']}/labels", json={"label": "malicious", "reason": "Original reviewed chain interpretation"}).json()
    login(client, "approver")
    client.post(f"/api/labels/{label['id']}/review", json={"decision": "approve", "reason": "Review original evidence independently"})
    login(client, "ml_engineer")
    fingerprint = client.get("/api/state").json()["learning"]["dataset_hash"]
    candidate = client.post("/api/learning/train", json={"dataset_hash": fingerprint, "reviewed": True}).json()
    assert candidate["status"] == "challenger"
    login(client, "analyst")
    correction = client.post(f"/api/incidents/{case['id']}/labels", json={"label": "benign", "reason": "New change-ticket evidence confirms legitimate activity"}).json()
    login(client, "approver")
    response = client.post(f"/api/labels/{correction['id']}/review", json={"decision": "approve", "reason": "Independently verified change-ticket evidence"})
    assert response.status_code == 200
    stored = app.state.store.get("models", candidate["id"])
    assert stored["data_review_required"]
    assert app.state.store.get("labels", label["id"])["status"] == "superseded"
    response = client.post(f"/api/models/{candidate['id']}/promote", json={"reason": "Attempt promotion after label changed"})
    assert response.status_code == 409 and response.json()["detail"] == "TRAINING_LABELS_CHANGED"
    assert client.get("/api/state").json()["overview"]["model_version"] == "rules-1.0"
