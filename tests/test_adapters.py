from datetime import datetime, timezone
import pytest
from app.adapters import normalize_wazuh, normalize_zeek


def test_wazuh_explicit_identity_mapping_no_raw_log_or_command():
    record = {"id": "123", "agent": {"id": "001"}, "timestamp": "2026-10-11T05:00:00Z",
        "full_log": "PRIVATE SECRET", "data": {"win": {"system": {"eventID": "4625", "channel": "Security"},
            "eventdata": {"targetUserName": "Alice", "ipAddress": "192.0.2.3", "password": "PRIVATE SECRET"}}}}
    mapping = {"001": {"asset_id": "bank-node-02", "address": "192.0.2.3", "identities": {"Alice": "directory:92"}}}
    result = normalize_wazuh(record, mapping)
    assert result["event_type"] == "login_failed"
    assert result["entity_id"] == "directory:92"
    assert "PRIVATE" not in str(result) and "Alice" not in str(result)
    assert normalize_wazuh(record, mapping)["id"] == result["id"]
    record["data"]["win"]["system"]["eventID"] = "9999"
    with pytest.raises(ValueError, match="UNSUPPORTED"):
        normalize_wazuh(record, mapping)


def test_zeek_availability_is_flow_end_not_start_and_identity_not_invented():
    record = {"uid": "C123", "ts": 1760000000, "duration": 120.0, "id.orig_h": "192.0.2.5", "id.resp_h": "203.0.113.4", "orig_bytes": 6000000}
    mapping = {"192.0.2.5": {"asset_id": "bank-node-02", "entity_id": "directory:92"}}
    result = normalize_zeek(record, mapping, ["192.0.2.0/24"])
    assert datetime.fromisoformat(result["event_time"].replace("Z", "+00:00")).timestamp() == 1760000120
    assert result["external"] and result["bytes_out"] == 6000000
    with pytest.raises(ValueError, match="UNMAPPED"):
        normalize_zeek(record, {}, ["192.0.2.0/24"])
    with pytest.raises(ValueError, match="INTERNAL_NETWORKS"):
        normalize_zeek(record, mapping, [])
