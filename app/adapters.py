"""Narrow offline adapters; unsupported vendor events fail explicitly.

Mappings must be supplied by the bank. No credentials, full_log, command lines,
packet contents or customer identifiers are retained in normalized output.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from .schemas import TelemetryEvent


def stable_id(source, record):
    return source + "-" + hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def normalize_wazuh(record, inventory_map):
    agent = str(record.get("agent", {}).get("id", ""))
    mapping = inventory_map.get(agent)
    if not mapping:
        raise ValueError("UNMAPPED_WAZUH_AGENT")
    win = record.get("data", {}).get("win", {})
    system, fields = win.get("system", {}), win.get("eventdata", {})
    event_code = str(system.get("eventID", ""))
    channel = str(system.get("channel", "")).lower()
    types = {"4624": "login_success", "4625": "login_failed", "4728": "privilege_change", "4732": "privilege_change", "4756": "privilege_change"}
    if event_code == "1" and "sysmon" in channel:
        kind, source = "process_start", "endpoint"
    elif event_code in types and channel in {"security", "microsoft-windows-security-auditing"}:
        kind, source = types[event_code], "identity"
    else:
        raise ValueError("UNSUPPORTED_WAZUH_EVENT")
    timestamp = system.get("systemTime") or record.get("timestamp")
    user = fields.get("targetUserName") if kind.startswith("login") else fields.get("subjectUserName") or fields.get("user")
    if not user or user == "-":
        raise ValueError("MISSING_IDENTITY_MAPPING")
    aliases = mapping.get("identities", {})
    if user not in aliases:
        raise ValueError("UNMAPPED_WAZUH_IDENTITY")
    # Process suspicion is an explicit curated rule-id mapping, never every shell.
    rule = str(record.get("rule", {}).get("id", ""))
    unusual = source == "endpoint" and rule in mapping.get("suspicious_process_rule_ids", [])
    ip = fields.get("ipAddress")
    if not ip or ip == "-":
        ip = mapping.get("address")
    if not ip:
        raise ValueError("MISSING_SOURCE_ADDRESS")
    row = {"id": stable_id("wazuh", {"agent": agent, "id": record.get("id"), "timestamp": timestamp, "code": event_code, "fields": fields}),
        "source": source, "event_type": kind, "event_time": timestamp, "asset_id": mapping["asset_id"],
        "entity_id": aliases[user], "src_ip": ip, "dst_ip": mapping["address"], "unusual_process": unusual,
        "privileged": aliases[user] in mapping.get("privileged_entities", [])}
    return TelemetryEvent.model_validate(row).model_dump()


def normalize_zeek(record, inventory_map, internal_cidrs):
    address = str(record.get("id.orig_h", ""))
    mapping = inventory_map.get(address)
    if not mapping or not mapping.get("entity_id"):
        # An IP cannot safely be assumed to be a particular user without a map.
        raise ValueError("UNMAPPED_ZEEK_ORIGIN")
    if not internal_cidrs:
        raise ValueError("INTERNAL_NETWORKS_REQUIRED")
    destination = ipaddress.ip_address(record["id.resp_h"])
    internal = [ipaddress.ip_network(cidr) for cidr in internal_cidrs]
    if not any(ipaddress.ip_address(address) in cidr for cidr in internal):
        raise ValueError("ORIGIN_NOT_INTERNAL")
    # conn.log describes an aggregate completed flow, not packet-level timing.
    started = float(record["ts"])
    duration = float(record.get("duration", 0))
    if duration < 0 or duration > 86400 * 30:
        raise ValueError("INVALID_FLOW_DURATION")
    at = datetime.fromtimestamp(started + duration, timezone.utc).isoformat()
    count = record.get("orig_bytes", 0)
    if type(count) is not int or count < 0:
        raise ValueError("INVALID_BYTE_COUNT")
    return TelemetryEvent.model_validate({"id": stable_id("zeek", {"uid": record["uid"], "ts": started, "origin": address, "destination": str(destination)}),
        "source": "network", "event_type": "network_connection", "event_time": at,
        "asset_id": mapping["asset_id"], "entity_id": mapping["entity_id"], "src_ip": address,
        "dst_ip": str(destination), "bytes_out": count, "external": not any(destination in cidr for cidr in internal)}).model_dump()
