"""Mode boundaries protect pilot traffic from demo models, data and sessions."""
from types import SimpleNamespace
import pytest

from app.service import SOCService
from app.store import Store


def service(store, mode):
    return SOCService(SimpleNamespace(mode=mode), store, SimpleNamespace())


def test_demo_directory_cannot_be_reopened_as_pilot(tmp_path):
    store = Store(tmp_path / "soc.db")
    service(store, "demo")
    before = len(store.audit_entries())
    with pytest.raises(ValueError, match="different mode"):
        service(store, "pilot")
    assert store.get("settings", "environment")["mode"] == "demo"
    assert len(store.audit_entries()) == before
    assert store.all("assets")


def test_fresh_pilot_restarts_same_mode_and_rejects_demo_switch(tmp_path):
    store = Store(tmp_path / "soc.db")
    service(store, "pilot")
    before = len(store.audit_entries())
    service(store, "pilot")
    assert len(store.audit_entries()) == before
    assert store.all("assets") == []
    assert store.get("settings", "environment")["mode"] == "pilot"
    with pytest.raises(ValueError, match="different mode"):
        service(store, "demo")


@pytest.mark.parametrize("kind,item", [
    ("assets", {"id": "legacy-node", "synthetic": True}),
    ("models", {"id": "legacy-model", "artifact": {"type": "logistic_regression"}, "synthetic": False}),
    ("training_rows", {"id": "legacy-row", "synthetic": True}),
])
def test_legacy_synthetic_or_trained_state_rejected_in_pilot(tmp_path, kind, item):
    store = Store(tmp_path / "soc.db")
    with store.transaction() as conn:
        store.put(kind, item, conn)
    with pytest.raises(ValueError, match="Pilot cannot open"):
        service(store, "pilot")
    assert store.get("settings", "environment") is None


def test_unmarked_legacy_session_cannot_become_pilot_session(tmp_path):
    store = Store(tmp_path / "soc.db")
    with store.transaction() as conn:
        conn.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", ("demo-session", "demo.admin", "admin", "csrf", "2099-01-01T00:00:00Z"))
    with pytest.raises(ValueError, match="Unmarked existing data"):
        service(store, "pilot")


def test_legacy_demo_can_bind_as_demo_and_then_cannot_switch(tmp_path):
    store = Store(tmp_path / "soc.db")
    with store.transaction() as conn:
        store.put("assets", {"id": "legacy-node", "synthetic": True}, conn)
    service(store, "demo")
    assert store.get("settings", "environment")["mode"] == "demo"
    with pytest.raises(ValueError, match="different mode"):
        service(store, "pilot")


def test_pilot_retains_inactive_candidate_but_rejects_unapproved_active_model(tmp_path):
    store = Store(tmp_path / "soc.db")
    service(store, "pilot")
    candidate = {"id": "pilot-candidate", "artifact": {"type": "logistic_regression"}, "status": "challenger", "synthetic": False}
    with store.transaction() as conn:
        store.put("models", candidate, conn)
    service(store, "pilot")
    candidate["status"] = "champion"
    with store.transaction() as conn:
        store.put("models", candidate, conn)
    with pytest.raises(ValueError, match="unapproved active model"):
        service(store, "pilot")
