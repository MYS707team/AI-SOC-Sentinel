"""Restore a verified backup into a new directory without carrying live sessions.

The checkpoint must have been retained independently. Its audit head and entry
count establish the expected chain, not confidentiality or full database
authenticity. The supplied key must be the securely retained original key;
historical backups do not contain a key fingerprint with which to prove that.
This tool preserves the stored demo/pilot environment and does not migrate it.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.store import Store, digest, utcnow


def restore_backup(backup: Path, key: Path, checkpoint: Path, output_dir: Path) -> dict:
    backup, key, checkpoint, output_dir = (Path(path).resolve() for path in (backup, key, checkpoint, output_dir))
    if output_dir.exists():
        raise ValueError("Output directory must be NEW and nonexistent; existing directories are never overwritten")
    if not output_dir.parent.is_dir():
        raise ValueError("Output parent directory must already exist")
    if not all(path.is_file() for path in (backup, key, checkpoint)):
        raise ValueError("Backup, original key and independent checkpoint must be existing files")
    key_bytes = key.read_bytes()
    if len(key_bytes) != 32:
        raise ValueError("Original pseudonym key must contain exactly 32 bytes")
    expected = json.loads(checkpoint.read_text(encoding="utf-8-sig"))
    if (not isinstance(expected, dict) or expected.get("valid") is not True
            or type(expected.get("checked")) is not int or expected["checked"] < 0
            or not isinstance(expected.get("head"), str) or not re.fullmatch(r"[0-9a-f]{64}", expected["head"])):
        raise ValueError("Checkpoint must contain a valid audit head and integer entry count")
    # Do not instantiate Store on the source: its constructor creates tables and
    # triggers. The existing verifier only reads when passed this connection.
    verifier = object.__new__(Store)
    source = sqlite3.connect(backup.as_uri() + "?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    try:
        source.execute("PRAGMA query_only=ON")
        source.execute("BEGIN")
        if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Backup SQLite integrity check failed")
        original = verifier.verify_audit(source)
        if (not original["valid"] or original["head"] != expected["head"]
                or original["checked"] != expected["checked"]):
            raise ValueError("Backup audit chain does not match the independent checkpoint")
        # Creation is exclusive and occurs only after all source checks passed.
        output_dir.mkdir(mode=0o700, exist_ok=False)
        pending = output_dir / ".restore-pending.db"
        destination = sqlite3.connect(pending)
        try:
            # Same source read transaction for verification and copying: a
            # concurrent source writer cannot change the verified snapshot.
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()
    restored = Store(pending)
    with restored.transaction() as connection:
        copied = restored.verify_audit(connection)
        if copied["head"] != original["head"] or copied["checked"] != original["checked"] or not copied["valid"]:
            raise ValueError("Copied database did not preserve the verified audit chain")
        revoked = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        connection.execute("DELETE FROM sessions")
        restored.audit("restore.operator", "system.backup_restored", "database", {
            "original_audit_head": original["head"], "original_audit_entries": original["checked"],
            "checkpoint_hash": digest(expected), "sessions_revoked": revoked,
            "environment_preserved": True, "mode_migration": False,
        }, connection)
        final = restored.verify_audit(connection)
        if not final["valid"] or final["checked"] != original["checked"] + 1:
            raise ValueError("Restoration audit verification failed")
    with restored.connect() as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    # Secrets are never included in stdout, logs, the restoration audit or report.
    with (output_dir / "pseudonym.key").open("xb") as stream:
        stream.write(key_bytes)
    os.chmod(output_dir / "pseudonym.key", 0o600)
    report = {"created_at": utcnow(), "valid": True, "original_head": original["head"],
              "original_entries": original["checked"], "restored_head": final["head"],
              "restored_entries": final["checked"], "sessions_revoked": revoked,
              "environment_preserved": True, "mode_migration": False,
              "key_validation": "32-byte length checked; operator must supply retained original key"}
    with (output_dir / "restore-report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    # Final database appears only after restoration, key copy and report succeed.
    # Hard-link creation is exclusive on Windows/POSIX and never overwrites.
    os.link(pending, output_dir / "soc.db")
    pending.unlink()
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = restore_backup(args.backup, args.key, args.checkpoint, args.output_dir)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as exc:
        parser.exit(1, f"Restore rejected: {exc}\n")
    print(f"Restored verified database into {args.output_dir}. Revoked {report['sessions_revoked']} sessions. Stored environment mode preserved.")


if __name__ == "__main__":
    main()
