"""Seeded, explicitly synthetic episodes for demonstration and pipeline checks.

Legitimate admin mistakes and backups overlap attack telemetry. Labels represent
simulated episode intent and are not derived from a detector score or threshold.
No claim about bank base rates or real-world detection follows from this data.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random

from .detection import featurize


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _episode(rng: random.Random, index: int, start: datetime, namespace: str, attack: bool) -> list[dict]:
    entity = f"{namespace}-identity-{index:05d}"
    criticality = rng.choices(["standard", "high", "critical"], [4, 4, 2])[0]
    # Some legitimate operations resemble attacks; some attacks lack a burst.
    difficult_benign = not attack and rng.random() < 0.19
    failure_count = rng.randint(2, 6) if attack and rng.random() < 0.78 else rng.randint(0, 2)
    if difficult_benign:
        failure_count = rng.randint(2, 5)
    event_types = ["login_failed"] * failure_count + ["login_success", "process_start", "privilege_change", "network_connection", "payment_access"]
    if not attack and not difficult_benign and rng.random() < 0.6:
        event_types.remove("privilege_change")
    unusual = rng.random() < (0.79 if attack else 0.42 if difficult_benign else 0.11)
    external = rng.random() < (0.84 if attack else 0.74 if difficult_benign else 0.46)
    privileged = rng.random() < (0.60 if attack else 0.66 if difficult_benign else 0.28)
    byte_count = int(rng.lognormvariate(15.8 if attack else 15.3 if difficult_benign else 12.2, 1.8))
    sequence = []
    for position, kind in enumerate(event_types):
        at = start + timedelta(seconds=position * 28 + rng.randint(0, 5))
        source = {"login_failed": "identity", "login_success": "identity", "process_start": "endpoint", "privilege_change": "identity", "network_connection": "network", "payment_access": "core_banking"}[kind]
        sequence.append({
            "id": f"{namespace}-{index:05d}-{position:02d}", "source": source, "event_type": kind,
            "event_time": _iso(at), "received_at": _iso(at + timedelta(seconds=1)),
            "asset_id": f"bank-node-{index % 24:02d}", "entity_id": entity,
            "src_ip": f"192.0.2.{index % 250 + 1}",
            "dst_ip": f"203.0.113.{(index * 7) % 250 + 1}" if external and kind == "network_connection" else f"198.51.100.{index % 250 + 1}",
            "bytes_out": min(byte_count, 1_000_000_000) if kind == "network_connection" else rng.randint(0, 5000),
            "privileged": privileged, "unusual_process": unusual if kind == "process_start" else False,
            "external": external if kind == "network_connection" else False,
            "criticality": criticality, "synthetic": True,
        })
    return sequence


def make_demo_events(seed: int = 41, count: int = 360) -> list[dict]:
    rng = random.Random(seed)
    # Minute anchor makes a demo current; IDs/values reproducible for a seed.
    base = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=max(480, count * 2))
    events, index = [], 0
    while len(events) < max(0, count):
        episode = _episode(rng, index, base + timedelta(minutes=index * 5), f"demo-{seed}", attack=index % 7 in (1, 4))
        events.extend(episode)
        index += 1
    return sorted(events[:count], key=lambda x: (x["received_at"], x["id"])) if count > 0 else []


def make_training_rows(seed: int = 41, count: int = 900) -> list[dict]:
    rng = random.Random(seed)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = []
    for index in range(max(0, count)):
        attack = rng.random() < 0.28
        episode = _episode(rng, index, base + timedelta(minutes=index * 45), f"train-{seed}", attack)
        # Decision point sampled independently of latent intent. One per entity.
        target = rng.choice(episode[-3:])
        at = datetime.fromisoformat(target["event_time"].replace("Z", "+00:00"))
        rows.append({"event_id": target["id"], "features": featurize(target, episode),
                     "label": int(attack), "event_time": target["event_time"],
                     "observed_at": target["received_at"],
                     "label_available_at": _iso(at + timedelta(hours=rng.randint(4, 12))),
                     "entity_id": target["entity_id"], "synthetic": True,
                     "provenance": "synthetic-ground-truth"})
    return rows
