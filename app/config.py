from dataclasses import dataclass, field
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("SOC_DATA_DIR", str(ROOT / ".runtime"))))
    mode: str = field(default_factory=lambda: os.environ.get("SOC_MODE", "demo"))
    origin: str = field(default_factory=lambda: os.environ.get("SOC_ORIGIN", "http://127.0.0.1:8765"))
    ingest_token: str = field(default_factory=lambda: os.environ.get("SOC_INGEST_TOKEN", ""))
    users_file: str = field(default_factory=lambda: os.environ.get("SOC_USERS_FILE", ""))
    testing: bool = False
    auto_seed: bool = True
    session_hours: int = 4
    max_body_bytes: int = 524288

    def validate(self):
        if self.mode not in {"demo", "pilot"}:
            raise ValueError("SOC_MODE must be demo or pilot; live response is unavailable")
        if self.mode == "pilot":
            if not self.origin.startswith("https://"):
                raise ValueError("Pilot requires an explicit HTTPS SOC_ORIGIN behind a TLS reverse proxy")
            if len(self.ingest_token) < 32 or not self.users_file:
                raise ValueError("Pilot requires SOC_INGEST_TOKEN (32+ characters) and SOC_USERS_FILE")
        self.data_dir.mkdir(parents=True, exist_ok=True)

