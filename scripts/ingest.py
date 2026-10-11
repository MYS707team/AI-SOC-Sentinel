"""Explicit authenticated submission of reviewed normalized NDJSON.

The operator supplies SOC_INGEST_TOKEN through environment/secret management.
Retries preserve event IDs; redirects and remote cleartext HTTP are refused.
"""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlparse
import httpx


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8765")
    args = parser.parse_args()
    token = os.environ.get("SOC_INGEST_TOKEN", "")
    parsed = urlparse(args.url)
    if len(token) < 32:
        parser.error("SOC_INGEST_TOKEN must be provided securely")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        parser.error("URL must not contain credentials, query or fragment")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
        parser.error("Remote destinations require HTTPS")
    count = 0
    with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as client:
        def send(batch):
            result = client.post(args.url.rstrip("/") + "/api/ingest/events", json={"events": batch}, headers={"Authorization": "Bearer " + token})
            if result.status_code != 200:
                raise SystemExit(f"Collector rejected batch with HTTP {result.status_code}. Input retained for review; no automatic retry.")
            return result.json()["accepted"]
        batch = []
        with args.input.open(encoding="utf-8-sig") as stream:
            for line in stream:
                if not line.strip():
                    continue
                if len(line) > 32000:
                    raise SystemExit("Normalized line exceeds 32 KB")
                batch.append(json.loads(line))
                if len(batch) >= 100:
                    count += send(batch)
                    batch = []
        if batch:
            count += send(batch)
    print(f"Accepted {count} events. Existing identical IDs were deduplicated.")


if __name__ == "__main__":
    main()
