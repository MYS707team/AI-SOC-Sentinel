from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app
from app.http_learning import load_public


def test_clean_install_has_model_dataset_and_real_hosted_defence(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, origin="https://soc.example",
                              hosted_demo=True, auto_seed=False))
    with TestClient(app, base_url="https://soc.example") as client:
        login = client.post("/api/auth/demo", json={"role": "admin"})
        assert login.status_code == 200
        assert "Secure" in login.headers["set-cookie"]
        client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        assert client.get("/healthz").json()["storage"] == "ephemeral"
        state = client.get("/api/lab/state").json()
        assert state["model_ready"]
        result = client.post("/api/lab/request", json={"path": "/search",
                             "payload": "'/**/OR/**/1=1-- ", "method": "GET"})
        assert result.status_code == 200
        assert result.json()["blocked"] and not result.json()["target_executed"]
        rows, manifest = load_public(tmp_path / "http" / "public.jsonl")
        assert len(rows) == manifest["rows"] > 10000


def test_hosted_flag_is_required_for_remote_demo_login(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, origin="https://soc.example", auto_seed=False))
    with TestClient(app, base_url="https://soc.example") as client:
        assert client.post("/api/auth/demo", json={"role": "admin"}).status_code == 403
