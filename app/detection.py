"""Decision-time features and transparent, evidence-backed SOC rules.

Scores are operational risk ranks, never calibrated breach probabilities. Inputs
are minimized normalized telemetry; no customer names, payloads or credentials.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math

EVENT_TYPES = ("login_failed", "login_success", "process_start", "network_connection", "privilege_change", "payment_access")
FEATURE_NAMES = tuple("is_" + x for x in EVENT_TYPES) + (
    "privileged", "unusual_process", "external", "criticality", "log_bytes_out",
    "failures_5m", "recent_login_10m", "recent_privilege_15m",
    "unusual_processes_15m", "external_connections_15m", "source_count_15m",
    "log_bytes_15m", "new_external_destination", "login_after_failures",
    "ordered_compromise_sequence",
)
CONTEXT_FEATURES = FEATURE_NAMES[11:]
FEATURE_SCHEMA = "soc-context-v1"


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _number(value: object, ceiling: float = 1e12) -> float:
    try:
        number = float(value)
        return min(ceiling, max(0.0, number)) if math.isfinite(number) else 0.0
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _visible_history(event: dict, history: list[dict]) -> list[dict]:
    """Same entity, earlier event time, already received; duplicates count once.

    Simultaneous event timestamps are conservatively excluded. Late-arriving
    events never rewrite an old decision; receipt time is a separate boundary.
    """
    event_time = parse_time(event["event_time"])
    decision_time = parse_time(event.get("received_at", event["event_time"]))
    entity = event.get("entity_id")
    if not entity:
        return []
    seen = {event.get("id")}
    visible = []
    for prior in history:
        if prior.get("entity_id") != entity or not prior.get("id") or prior.get("id") in seen:
            continue
        try:
            ts = parse_time(prior["event_time"])
            received = parse_time(prior.get("received_at", prior["event_time"]))
        except (ValueError, KeyError, TypeError):
            continue
        age = (event_time - ts).total_seconds()
        if 0 < age <= 86400 and received <= decision_time and received >= ts:
            seen.add(prior["id"])
            visible.append(prior)
    return sorted(visible, key=lambda x: (parse_time(x["event_time"]), x["id"]))


def featurize(event: dict, history: list[dict]) -> dict[str, float]:
    now = parse_time(event["event_time"])
    prior = _visible_history(event, history)
    recent = [p for p in prior if (now - parse_time(p["event_time"])).total_seconds() <= 900]
    failures = [p for p in recent if p.get("event_type") == "login_failed" and (now - parse_time(p["event_time"])).total_seconds() <= 300]
    logins = [p for p in recent if p.get("event_type") == "login_success" and (now - parse_time(p["event_time"])).total_seconds() <= 600]
    # Explicit ordered pattern: >=3 failures -> success -> unusual process.
    ordered = False
    success_after_failures = event.get("event_type") == "login_success" and len(failures) >= 3
    for login in logins:
        login_at = parse_time(login["event_time"])
        preceding = [p for p in recent if p.get("event_type") == "login_failed" and 0 < (login_at - parse_time(p["event_time"])).total_seconds() <= 300]
        if len(preceding) >= 3:
            success_after_failures = True
            ordered = ordered or any(p.get("event_type") == "process_start" and p.get("unusual_process") is True and parse_time(p["event_time"]) > login_at for p in recent)
    destination = event.get("dst_ip")
    features = {"is_" + name: float(event.get("event_type") == name) for name in EVENT_TYPES}
    features.update({
        "privileged": float(event.get("privileged") is True),
        "unusual_process": float(event.get("unusual_process") is True),
        "external": float(event.get("external") is True),
        "criticality": {"standard": 0.0, "high": 0.5, "critical": 1.0}.get(event.get("criticality"), 0.0),
        "log_bytes_out": math.log1p(_number(event.get("bytes_out", 0))),
        "failures_5m": float(min(50, len(failures))),
        "recent_login_10m": float(bool(logins)),
        "recent_privilege_15m": float(any(p.get("event_type") == "privilege_change" for p in recent)),
        "unusual_processes_15m": float(min(50, sum(p.get("event_type") == "process_start" and p.get("unusual_process") is True for p in recent))),
        "external_connections_15m": float(min(50, sum(p.get("event_type") == "network_connection" and p.get("external") is True for p in recent))),
        "source_count_15m": float(len({p.get("source") for p in recent if p.get("source")})),
        "log_bytes_15m": math.log1p(min(1e13, sum(_number(p.get("bytes_out", 0)) for p in recent))),
        "new_external_destination": float(event.get("external") is True and bool(destination) and not any(p.get("dst_ip") == destination and p.get("event_type") == "network_connection" for p in prior)),
        "login_after_failures": float(success_after_failures),
        "ordered_compromise_sequence": float(ordered),
    })
    return features


def rules_from_features(f: dict) -> tuple[float, list[str], list[str]]:
    score, reasons, techniques = 8.0, [], []
    def add(value: float, code: str, *mitre: str) -> None:
        nonlocal score
        score = max(score, value)
        reasons.append(code)
        techniques.extend(mitre)
    if f.get("failures_5m", 0) >= 3 and (f.get("is_login_failed") or f.get("is_login_success")):
        add(58, "AUTH_FAILURE_BURST", "T1110")
    if f.get("login_after_failures") and f.get("is_login_success"):
        add(72, "SUCCESS_AFTER_FAILURES", "T1078")
    if f.get("is_process_start") and f.get("unusual_process"):
        add(78 if f.get("privileged") else 46, "UNUSUAL_PROCESS", "T1059")
    if f.get("is_network_connection") and f.get("external") and f.get("log_bytes_out", 0) >= math.log1p(5_000_000):
        add(87 if f.get("unusual_processes_15m") else 53, "EXTERNAL_DATA_TRANSFER", "T1041")
    if f.get("is_privilege_change") and f.get("login_after_failures"):
        add(84, "PRIVILEGE_AFTER_LOGIN", "T1098")
    if f.get("is_payment_access") and f.get("recent_privilege_15m") and f.get("unusual_processes_15m"):
        add(91, "PAYMENT_SYSTEM_ACCESS", "T1078")
    if f.get("ordered_compromise_sequence") and (f.get("is_network_connection") or f.get("is_payment_access") or f.get("is_privilege_change")):
        add(94, "CROSS_SOURCE_SEQUENCE", "T1078", "T1059")
    if not reasons:
        reasons = ["NO_STRONG_SIGNAL"]
    return score, reasons, sorted(set(techniques))


def detect_event(event: dict, history: list[dict], artifact: dict | None = None) -> dict:
    features = featurize(event, history)
    rule_score, reasons, mitre = rules_from_features(features)
    model_score = None
    model_alert = False
    if artifact:
        from .learning import score_artifact
        try:
            threshold = float(artifact["threshold"])
            if not math.isfinite(threshold) or not 0 <= threshold <= 1.00000001:
                raise ValueError("Invalid decision threshold")
            model_score = score_artifact(features, artifact)
            if model_score >= threshold:
                model_alert = True
                reasons = [r for r in reasons if r != "NO_STRONG_SIGNAL"] + ["MODEL_ELEVATED"]
        except (ValueError, TypeError, KeyError, OverflowError):
            model_score, model_alert = None, False
            reasons.append("MODEL_UNAVAILABLE")
    score = round(max(rule_score, model_score * 100 if model_score is not None else 0), 2)
    severity = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"
    visible = _visible_history(event, history)
    now = parse_time(event["event_time"])
    evidence = [p["id"] for p in visible if (now - parse_time(p["event_time"])).total_seconds() <= 900]
    return {"score": score, "severity": severity, "reason_codes": reasons,
            "alert": rule_score >= 40 or model_alert, "model_alert": model_alert,
            "evidence_ids": (evidence[-19:] + [event["id"]]), "mitre": mitre,
            "features": features, "rule_score": rule_score,
            "model_score": round(model_score * 100, 2) if model_score is not None else None}
