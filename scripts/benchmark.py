"""Single-process local smoke latency measurement, NOT a bank throughput claim."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import platform
import statistics
import sys
from tempfile import TemporaryDirectory
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app


def main():
    with TemporaryDirectory() as folder:
        app = create_app(Settings(data_dir=Path(folder), testing=True, ingest_token="benchmark-only-not-a-real-secret" * 2))
        with TestClient(app) as client:
            client.post("/api/auth/demo", json={"role": "auditor"})
            latencies = []
            for _ in range(20):
                start = time.perf_counter()
                assert client.get("/api/state").status_code == 200
                latencies.append((time.perf_counter() - start) * 1000)
            at = datetime.now(timezone.utc) - timedelta(minutes=10)
            events = [{"id": f"bench-{i}", "source": "identity", "event_type": "login_success", "asset_id": "bank-node-02",
                "entity_id": f"bench-entity-{i%40}", "event_time": (at + timedelta(seconds=i)).isoformat()} for i in range(200)]
            start = time.perf_counter()
            response = client.post("/api/ingest/events", json={"events": events}, headers={"Authorization": "Bearer " + "benchmark-only-not-a-real-secret" * 2})
            elapsed = time.perf_counter() - start
            assert response.status_code == 200
            results = {"date": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(), "python": platform.python_version(),
                "conditions": "FastAPI TestClient in-process, single worker, 360 seeded events; no TLS/network/multi-user load",
                "state_20_requests_ms": {"median": round(statistics.median(latencies), 2), "p95_nearest_rank": round(sorted(latencies)[18], 2)},
                "single_200_event_batch_seconds": round(elapsed, 3), "accepted": response.json()["accepted"],
                "sustained_eps": None, "bank_production_slo_validated": False, "audit_valid": app.state.store.verify_audit()["valid"]}
    output = Path(__file__).resolve().parents[1] / "research" / "latency-smoke.json"
    output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
