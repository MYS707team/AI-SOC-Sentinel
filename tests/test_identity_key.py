from types import SimpleNamespace
import pytest
from app.security import Security
from app.store import Store


def test_missing_or_invalid_key_cannot_silently_change_existing_identities(tmp_path):
    store = Store(tmp_path / 'soc.db')
    settings = SimpleNamespace(data_dir=tmp_path, users_file='')
    original = Security(settings, store)
    identity = original.pseudonym('account-01')
    retained_key = (tmp_path / 'pseudonym.key').read_bytes()
    with store.transaction() as conn:
        store.put('events', {'id': 'event-1', 'entity_id': identity}, conn)
    (tmp_path / 'pseudonym.key').unlink()
    with pytest.raises(ValueError, match='original pseudonym.key'):
        Security(settings, store)
    assert not (tmp_path / 'pseudonym.key').exists()
    (tmp_path / 'pseudonym.key').write_bytes(b'bad-key')
    with pytest.raises(ValueError, match='32 bytes'):
        Security(settings, store)
    (tmp_path / 'pseudonym.key').write_bytes(retained_key)
    assert Security(settings, store).pseudonym('account-01') == identity
