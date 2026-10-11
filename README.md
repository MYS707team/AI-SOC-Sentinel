# AI-SOC Sentinel

Trained HTTP anomaly detection, real loopback attack lab, inline request denial, SOC inbox, independent analyst feedback review, dataset collection and governed retraining.

47 regression tests passed. Public CSIC HTTP 2010 lab data; not production bank data. Read [the judge guide](docs/LIVE_LAB_UZ.md) for measured results and limitations.

## Run

Python 3.12+: `pip install -r requirements.txt`, then `python -m uvicorn app.main:app --host 127.0.0.1 --port 8765 --workers 1 --no-proxy-headers`. Open http://127.0.0.1:8765/#lab. Windows: `start.cmd`.

The bundled portable JSON model is trained and ready. Public numeric training features are bundled with source checksums. For independent reconstruction, run `python scripts/train_http.py --download`. No real bank logs, secrets, databases or unrelated website files are included.

## Verification

`python -m pytest -q` and `node scripts/check_frontend.mjs`. HTTP integration tests require the prepared model in `.runtime/http`; application startup installs the bundled model and numeric public features there.

## Hosting

This is a stateful Python application. The complete lab requires persistent storage, a single worker and localhost sockets. Vercel alone does not provide persistent SQLite storage. Do not represent a static frontend or ephemeral serverless deployment as the full durable system.


### Vercel demonstration

The Vercel entrypoint runs the trained detector and real loopback laboratory in an explicitly disposable hosted demo. It uses temporary shared storage: sessions, feedback, retraining and audit data may reset when the function restarts or scales. Export reviewed datasets before closing. Local/Docker runs retain SQLite data in SOC_DATA_DIR. This deployment is not a durable bank service.
