"""Vercel demonstration entrypoint; local deployments use app.main directly."""
import os

# This entrypoint deliberately exposes only a disposable training laboratory.
# SOC_HOSTED_DEMO never enables pilot access or external attack targets.
os.environ.setdefault("SOC_DATA_DIR", "/tmp/ai-soc-demo")
os.environ.setdefault("SOC_MODE", "demo")
os.environ.setdefault("SOC_HOSTED_DEMO", "1")
os.environ.setdefault("SOC_ORIGIN", "https://" + os.environ.get("VERCEL_URL", "localhost"))

from app.main import app
