# AI-SOC Sentinel

Trained HTTP anomaly detection, real loopback attack lab, inline request denial, SOC inbox, independent analyst feedback review, dataset collection and governed retraining.

47 regression tests passed. Public CSIC HTTP 2010 lab data; not production bank data. Read [the judge guide](docs/LIVE_LAB_UZ.md) for measured results and limitations.

## Run

Python 3.12+: `pip install -r requirements.txt`, then `python -m uvicorn app.main:app --host 127.0.0.1 --port 8765 --workers 1 --no-proxy-headers`. Open http://127.0.0.1:8765/#lab. Windows: `start.cmd`.

The bundled portable JSON model is trained and ready. For retraining, run `python scripts/train_http.py --download` once to fetch the checksum-pinned public research dataset. No real bank logs, secrets, databases or unrelated website files are included.

## Verification

`python -m pytest -q` and `node scripts/check_frontend.mjs`. HTTP integration tests require the prepared model in `.runtime/http`; the launcher installs the bundled model there.

## Hosting

This is a stateful Python application. The complete lab requires persistent storage, a single worker and localhost sockets. Vercel alone does not provide persistent SQLite storage. Do not represent a static frontend or ephemeral serverless deployment as the full durable system.
