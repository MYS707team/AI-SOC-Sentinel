"""Consistent SQLite backup with a separately retained audit-head checkpoint."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.store import Store, utcnow


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.data_dir / "soc.db"
    if not source.exists() or args.output.exists():
        parser.error("Source must exist and output must be a NEW file")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source) as src, sqlite3.connect(args.output) as dest:
        src.backup(dest)
    src.close()
    dest.close()
    verified = Store(args.output).verify_audit()
    args.output.with_suffix(".checkpoint.json").write_text(json.dumps({"created_at": utcnow(), **verified}, indent=2), encoding="utf-8")
    print("Database backup created. Retain pseudonym.key securely and anchor the checkpoint outside this host.")
    if not verified["valid"]:
        raise SystemExit("Backup audit verification failed")


if __name__ == "__main__":
    main()
