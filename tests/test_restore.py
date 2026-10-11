import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from app.store import Store
from scripts.restore import restore_backup


@pytest.fixture
def backup_fixture(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source = Store(source_dir / "soc.db")
    key = source_dir / "pseudonym.key"
    key.write_bytes(bytes(range(32)))
    with source.transaction() as connection:
        source.put("settings", {"id": "environment", "mode": "demo"}, connection)
        source.put("events", {"id": "event-a", "synthetic": True, "value": "original"}, connection)
        source.audit("fixture", "fixture.created", "event-a", {"synthetic": True}, connection)
        connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", ("session-hash", "user-a", "admin", "csrf", "2099-01-01T00:00:00Z"))
    backup = tmp_path / "backup.db"
    command = [sys.executable, str(Path(__file__).resolve().parents[1] / "scripts" / "backup.py"),
               "--data-dir", str(source_dir), "--output", str(backup)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return source, backup, key, backup.with_suffix(".checkpoint.json")


def test_backup_restore_revokes_sessions_keeps_original_chain_and_source(tmp_path, backup_fixture):
    source, backup, key, checkpoint = backup_fixture
    original_hash = hashlib.sha256(backup.read_bytes()).hexdigest()
    before = source.verify_audit()
    target = tmp_path / "restored"
    report = restore_backup(backup, key, checkpoint, target)
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == original_hash
    assert source.verify_audit() == before
    assert (target / "pseudonym.key").read_bytes() == key.read_bytes()
    assert not (target / ".restore-pending.db").exists()
    restored = Store(target / "soc.db")
    assert restored.verify_audit()["valid"]
    assert restored.verify_audit()["checked"] == before["checked"] + 1
    assert restored.get("events", "event-a")["value"] == "original"
    assert restored.get("settings", "environment")["mode"] == "demo"
    assert report["sessions_revoked"] == 1
    with restored.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    with source.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    last = restored.audit_entries()[-1]
    assert last["action"] == "system.backup_restored"
    assert last["prev_hash"] == before["head"]
    assert last["details"]["mode_migration"] is False
    assert key.read_bytes().hex() not in (target / "restore-report.json").read_text()


@pytest.mark.parametrize("field,value", [("head", "0" * 64), ("checked", 77), ("valid", False)])
def test_mismatched_checkpoint_rejected_before_output_creation(tmp_path, backup_fixture, field, value):
    _, backup, key, checkpoint = backup_fixture
    expected = json.loads(checkpoint.read_text())
    expected[field] = value
    checkpoint.write_text(json.dumps(expected))
    target = tmp_path / "rejected"
    with pytest.raises(ValueError, match="[Cc]heckpoint|checkpoint"):
        restore_backup(backup, key, checkpoint, target)
    assert not target.exists()


def test_existing_target_never_overwritten(tmp_path, backup_fixture):
    _, backup, key, checkpoint = backup_fixture
    target = tmp_path / "existing"
    target.mkdir()
    sentinel = target / "soc.db"
    sentinel.write_bytes(b"DO NOT OVERWRITE")
    with pytest.raises(ValueError, match="NEW"):
        restore_backup(backup, key, checkpoint, target)
    assert sentinel.read_bytes() == b"DO NOT OVERWRITE"


def test_wrong_key_length_rejected_without_output(tmp_path, backup_fixture):
    _, backup, _, checkpoint = backup_fixture
    wrong = tmp_path / "wrong.key"
    wrong.write_bytes(b"short-key")
    target = tmp_path / "rejected"
    with pytest.raises(ValueError, match="32 bytes"):
        restore_backup(backup, wrong, checkpoint, target)
    assert not target.exists()


def test_tampered_chain_rejected_read_only(tmp_path, backup_fixture):
    _, backup, key, checkpoint = backup_fixture
    connection = sqlite3.connect(backup)
    try:
        connection.execute("DROP TRIGGER audit_no_update")
        connection.execute("UPDATE audit SET actor='tampered'")
        connection.commit()
    finally:
        connection.close()
    before = hashlib.sha256(backup.read_bytes()).hexdigest()
    target = tmp_path / "rejected"
    with pytest.raises(ValueError, match="audit chain"):
        restore_backup(backup, key, checkpoint, target)
    assert not target.exists()
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == before
