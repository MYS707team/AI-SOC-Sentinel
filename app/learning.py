"""Governed batch continual learning with reproducible, inspectable artifacts.

New analyst labels trigger a *candidate*, never automatic production promotion.
Transforms fit on training only; thresholds use validation only. Two later,
entity-disjoint cohorts measure retention and recent behavior. Synthetic results
are useful pipeline evidence, not a bank acceptance or a calibrated probability.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import random
from typing import Any

from .detection import CONTEXT_FEATURES, FEATURE_NAMES, FEATURE_SCHEMA, parse_time, rules_from_features

SEED = 41
PURGE_SECONDS = 900
VALIDATION_FPR_LIMIT = 0.10  # Provisional demo operating policy, not a bank SLA.
MIN_TRAIN = 200
MIN_HOLDOUT = 60


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _id_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _vector(features: dict, names: list | tuple) -> list[float]:
    values = []
    for name in names:
        value = float(features.get(name, 0.0))
        if not math.isfinite(value) or abs(value) > 1e14:
            raise ValueError("Features must be finite bounded numbers")
        values.append(value)
    return values


def score_artifact(features: dict, artifact: dict) -> float:
    """Portable JSON inference, no deserialization of executable objects."""
    if artifact.get("schema") != FEATURE_SCHEMA or artifact.get("type") != "logistic_regression":
        raise ValueError("Unsupported model schema or type")
    names = artifact.get("feature_names", [])
    if not isinstance(names, list) or not names or len(set(names)) != len(names) or not set(names).issubset(FEATURE_NAMES):
        raise ValueError("Unknown feature layout")
    weights, means, scales = artifact["weights"], artifact["means"], artifact["scales"]
    if not all(isinstance(a, list) and len(a) == len(names) for a in (weights, means, scales)):
        raise ValueError("Inconsistent artifact dimensions")
    intercept = float(artifact["intercept"])
    if not math.isfinite(intercept):
        raise ValueError("Invalid intercept")
    score = intercept
    for value, weight, mean, scale in zip(_vector(features, names), weights, means, scales):
        weight, mean, scale = float(weight), float(mean), float(scale)
        if not all(math.isfinite(v) for v in (weight, mean, scale)) or scale <= 0:
            raise ValueError("Invalid model transform")
        score += max(-100.0, min(100.0, (value - mean) / scale)) * weight
    score = max(-60.0, min(60.0, score))
    return 1.0 / (1.0 + math.exp(-score))


def _prepare(rows: list[dict], now: datetime) -> tuple[list[dict], dict]:
    accepted, seen = [], {}
    counts = {"invalid": 0, "duplicates": 0, "conflicting_duplicates": 0, "unmatured": 0}
    conflicting_ids = set()
    for row in rows:
        try:
            if not isinstance(row, dict) or type(row.get("label")) is not int or row["label"] not in (0, 1):
                raise ValueError("Only explicitly reviewed binary labels are eligible")
            if not row.get("event_id") or not row.get("entity_id") or not row.get("provenance"):
                raise ValueError("Missing provenance or grouping key")
            if not isinstance(row.get("features"), dict) or set(row["features"]) != set(FEATURE_NAMES):
                raise ValueError("Feature schema mismatch")
            features = dict(zip(FEATURE_NAMES, _vector(row["features"], FEATURE_NAMES)))
            event_time, observed_at, label_at = (parse_time(row[name]) for name in ("event_time", "observed_at", "label_available_at"))
            if not event_time <= observed_at <= label_at:
                raise ValueError("Invalid observation or label chronology")
            if observed_at > now or label_at > now:
                counts["unmatured"] += 1
                continue
            normalized = {"event_id": str(row["event_id"]), "entity_id": str(row["entity_id"]), "features": features,
                          "label": row["label"], "event_time": _iso(event_time), "observed_at": _iso(observed_at),
                          "label_available_at": _iso(label_at), "synthetic": row.get("synthetic") is True,
                          "provenance": str(row["provenance"])}
            checksum = _digest(normalized)
            if normalized["event_id"] in seen:
                if seen[normalized["event_id"]] == checksum:
                    counts["duplicates"] += 1
                else:
                    counts["conflicting_duplicates"] += 1
                    conflicting_ids.add(normalized["event_id"])
                continue
            seen[normalized["event_id"]] = checksum
            accepted.append(normalized)
        except (TypeError, ValueError, KeyError, OverflowError):
            counts["invalid"] += 1
    accepted = [r for r in accepted if r["event_id"] not in conflicting_ids]
    return sorted(accepted, key=lambda r: (r["event_time"], r["event_id"])), counts


def _split(rows: list[dict], now: datetime) -> tuple[dict[str, list], dict]:
    """Forward blocks, all cross-boundary entities purged, label-time cutoffs."""
    names = ("train", "validation", "historical_replay", "final_recent")
    n = len(rows)
    if n < 8:
        return {name: [] for name in names}, {"error": "Too few mature records for four forward cohorts"}
    indices = [0, int(n * 0.55), int(n * 0.70), int(n * 0.85), n]
    cutoffs = [parse_time(rows[index]["event_time"]) for index in indices[1:-1]]
    gap = timedelta(seconds=PURGE_SECONDS)
    membership: dict[str, set] = {}
    for part, lo, hi in zip(names, indices[:-1], indices[1:]):
        for row in rows[lo:hi]:
            membership.setdefault(row["entity_id"], set()).add(part)
    overlap = {entity for entity, parts in membership.items() if len(parts) > 1}
    groups, purged = {}, {"boundary_entities": len(overlap), "entity_rows": 0, "gap_or_label_rows": 0}
    for part_index, (name, lo, hi) in enumerate(zip(names, indices[:-1], indices[1:])):
        selected = []
        for row in rows[lo:hi]:
            if row["entity_id"] in overlap:
                purged["entity_rows"] += 1
                continue
            at = parse_time(row["event_time"])
            label_at = parse_time(row["label_available_at"])
            # A label used to fit or tune must exist before the next cohort.
            end = cutoffs[part_index] - gap if part_index < 3 else now
            start = cutoffs[part_index - 1] + gap if part_index else None
            if at >= end or (start is not None and at < start) or label_at > end:
                purged["gap_or_label_rows"] += 1
                continue
            selected.append(row)
        groups[name] = selected
    manifest = {
        "protocol": "forward-55-15-15-15/entity-disjoint/label-mature/purged",
        "seed": SEED, "purge_seconds": PURGE_SECONDS, "as_of": _iso(now),
        "time_cutoffs": [_iso(t) for t in cutoffs], "purged": purged,
        "input_checksum": _digest(rows), "threshold_source": "validation_only",
        "final_reuse_warning": "An identical final cohort in another run is development evidence, not independent confirmation.",
        "cohorts": {},
    }
    for name, selected in groups.items():
        manifest["cohorts"][name] = {"count": len(selected), "positives": sum(r["label"] for r in selected),
                                       "entities": len({r["entity_id"] for r in selected}),
                                       "checksum": _digest(selected),
                                       "event_ids": [r["event_id"] for r in selected],
                                       "start": selected[0]["event_time"] if selected else None,
                                       "end": selected[-1]["event_time"] if selected else None}
    return groups, manifest


def _metric(rows: list[dict], scores: list[float], threshold: float) -> dict:
    from sklearn.metrics import average_precision_score, brier_score_loss
    truth = [r["label"] for r in rows]
    predicted = [int(score >= threshold) for score in scores]
    tp = sum(y == 1 and p == 1 for y, p in zip(truth, predicted))
    fp = sum(y == 0 and p == 1 for y, p in zip(truth, predicted))
    tn = sum(y == 0 and p == 0 for y, p in zip(truth, predicted))
    fn = sum(y == 1 and p == 0 for y, p in zip(truth, predicted))
    return {"support": len(rows), "positives": tp + fn, "negatives": tn + fp,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "threshold": round(float(threshold), 8),
            "precision": round(tp / (tp + fp), 6) if tp + fp else 0.0,
            "recall": round(tp / (tp + fn), 6) if tp + fn else 0.0,
            "fpr": round(fp / (fp + tn), 6) if fp + tn else 0.0,
            "pr_auc": round(float(average_precision_score(truth, scores)), 6) if tp + fn and tn + fp else None,
            "pr_auc_definition": "average_precision (non-interpolated)",
            "brier": round(float(brier_score_loss(truth, scores)), 6) if rows else None,
            "brier_interpretation": "diagnostic only; scores are not calibrated probabilities",
            "alert_rate": round((tp + fp) / len(rows), 6) if rows else 0.0}


def _threshold(rows: list[dict], scores: list[float]) -> float:
    # Highest recall satisfying provisional false-positive capacity on validation.
    # Include abstention; ties favor precision then the higher threshold.
    choices = sorted(set(scores) | {1.00000001})
    best, chosen = (-1.0, -1.0, -1.0), 1.00000001
    for value in choices:
        truth = [r["label"] for r in rows]
        tp = sum(y == 1 and score >= value for y, score in zip(truth, scores))
        fp = sum(y == 0 and score >= value for y, score in zip(truth, scores))
        negatives, positives = len(truth) - sum(truth), sum(truth)
        if fp / max(1, negatives) <= VALIDATION_FPR_LIMIT:
            utility = (tp / max(1, positives), tp / max(1, tp + fp), value)
            if utility > best:
                best, chosen = utility, value
    return chosen


def _hybrid_metric(rows: list[dict], artifact: dict) -> dict:
    model_scores = [score_artifact(row["features"], artifact) for row in rows]
    rule_scores = [rules_from_features(row["features"])[0] / 100 for row in rows]
    decisions = [float(rule >= 0.4 or model >= artifact["threshold"]) for rule, model in zip(rule_scores, model_scores)]
    metrics = _metric(rows, decisions, 0.5)
    metrics.update({"threshold": {"rule": 0.4, "model": artifact["threshold"], "operator": "OR"},
                    "pr_auc": None, "brier": None,
                    "pr_auc_definition": "Not reported for a boolean hybrid policy",
                    "brier_interpretation": "Not applicable: two independently thresholded detectors"})
    return metrics


def _fit(rows: list[dict], names: list[str], model_name: str) -> dict:
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    x = np.asarray([_vector(r["features"], names) for r in rows])
    y = np.asarray([r["label"] for r in rows])
    transform = StandardScaler().fit(x)
    scaled = np.clip(transform.transform(x), -100, 100)
    model = LogisticRegression(C=0.5, max_iter=1000, random_state=SEED).fit(scaled, y)
    if list(model.classes_) != [0, 1]:
        raise ValueError("Binary class mapping changed")
    artifact = {"schema": FEATURE_SCHEMA, "type": "logistic_regression", "name": model_name,
                "feature_names": names, "weights": model.coef_[0].tolist(),
                "intercept": float(model.intercept_[0]), "means": transform.mean_.tolist(),
                "scales": transform.scale_.tolist(), "class_mapping": {"0": "reviewed_benign", "1": "reviewed_malicious"},
                "threshold": 0.5, "score_semantics": "uncalibrated_risk_rank",
                "training_checksum": _digest(rows),
                "training_event_hashes": [_id_hash(r["event_id"]) for r in rows],
                "training_entity_hashes": sorted({_id_hash(r["entity_id"]) for r in rows}),
                "production_eligible": False, "deployment_scope": "demo_only"}
    artifact["version"] = "candidate-" + _digest(artifact)[:16]
    # Check exact exported inference parity, not just that serialization succeeds.
    native = model.predict_proba(scaled)[:, list(model.classes_).index(1)]
    if max(abs(float(a) - score_artifact(r["features"], artifact)) for a, r in zip(native, rows)) > 1e-10:
        raise ValueError("Exported inference differs from training model")
    return artifact


def _replay_sample(rows: list[dict], cap: int = 20000) -> list[dict]:
    """Bounded deterministic old/recent replay; no labels from holdouts."""
    if len(rows) <= cap:
        return rows
    rng = random.Random(SEED)
    midpoint = len(rows) // 2
    old = rng.sample(rows[:midpoint], min(midpoint, cap // 2))
    recent = rng.sample(rows[midpoint:], min(len(rows) - midpoint, cap - len(old)))
    return sorted(old + recent, key=lambda r: (r["event_time"], r["event_id"]))


def train_candidate(rows: list[dict], previous_artifact: dict | None = None, now: str | None = None) -> dict:
    as_of = parse_time(now) if now else datetime.now(timezone.utc)
    prepared, quality = _prepare(rows, as_of)
    groups, manifest = _split(prepared, as_of)
    manifest["data_quality"] = quality
    gates = []
    def gate(name: str, passed: bool, observed: Any, required: Any) -> None:
        gates.append({"name": name, "passed": bool(passed), "observed": observed, "required": required})
    gate("data_integrity", quality["invalid"] + quality["conflicting_duplicates"] == 0, quality, "No invalid records or conflicting event IDs")
    for name, subset in groups.items():
        positives, negatives = sum(r["label"] for r in subset), sum(1 - r["label"] for r in subset)
        minimum = MIN_TRAIN if name == "train" else MIN_HOLDOUT
        gate("support_" + name, len(subset) >= minimum and min(positives, negatives) >= 12,
             {"rows": len(subset), "positives": positives, "negatives": negatives}, {"rows": minimum, "each_class": 12})
    result = {"artifact": None, "metrics": {}, "gates": gates, "eligible": False,
              "production_eligible": False, "deployment_scope": "demo_only", "split_manifest": manifest,
              "limitations": ["Synthetic benchmarks do not establish bank detection quality or incident prevalence.",
                              "Production promotion requires representative independently labeled bank data, external validation, approval and a monitored canary.",
                              "Reusing a final cohort turns it into development evidence.",
                              "Risk scores are uncalibrated; no automatic blocking or online weight mutation is permitted."],
              "production_blockers": ["bank_representative_external_validation", "independent_model_risk_approval", "monitored_bank_canary"]}
    if any(r["synthetic"] for r in prepared):
        result["production_blockers"].append("synthetic_training_or_evaluation")
    if not all(g["passed"] for g in gates):
        result["status"] = "blocked_insufficient_or_invalid_data"
        return result
    train = _replay_sample(groups["train"])
    manifest["training_buffer"] = {"strategy": "all_until_20000_then_equal_old_recent_seeded_reservoir", "selected": len(train), "checksum": _digest(train)}
    validation = groups["validation"]
    models = {
        "pointwise_logistic": _fit(train, [n for n in FEATURE_NAMES if n not in CONTEXT_FEATURES], "pointwise_logistic"),
        "contextual_logistic": _fit(train, list(FEATURE_NAMES), "contextual_logistic"),
    }
    validation_scores = {name: [score_artifact(r["features"], artifact) for r in validation] for name, artifact in models.items()}
    validation_metrics = {}
    for name, artifact in models.items():
        artifact["threshold"] = _threshold(validation, validation_scores[name])
        validation_metrics[name] = _metric(validation, validation_scores[name], artifact["threshold"])
    # Frozen before reading either later cohort. No final-test hyperparameter tuning.
    selected_name = max(models, key=lambda name: (validation_metrics[name]["recall"], validation_metrics[name]["pr_auc"], name))
    selected = models[selected_name]
    selected["validation_checksum"] = manifest["cohorts"]["validation"]["checksum"]
    selected["parent_version"] = previous_artifact.get("version") if previous_artifact else None
    selected["version"] = "candidate-" + _digest({k: v for k, v in selected.items() if k != "version"})[:16]
    rule_validation = [rules_from_features(r["features"])[0] / 100 for r in validation]
    rule_threshold = _threshold(validation, rule_validation)
    comparisons = {}
    for cohort in ("historical_replay", "final_recent"):
        subset = groups[cohort]
        comparisons[cohort] = {
            "rules": _metric(subset, [rules_from_features(r["features"])[0] / 100 for r in subset], rule_threshold),
            "rules_operational": _metric(subset, [rules_from_features(r["features"])[0] / 100 for r in subset], 0.4),
            "operational_hybrid": _hybrid_metric(subset, selected),
            **{name: _metric(subset, [score_artifact(r["features"], artifact) for r in subset], artifact["threshold"]) for name, artifact in models.items()},
        }
    candidate = comparisons["final_recent"][selected_name]
    baseline = comparisons["final_recent"]["rules"]
    replay = comparisons["historical_replay"][selected_name]
    gate("recent_precision", candidate["precision"] >= 0.50, candidate["precision"], ">=0.50 provisional demo gate")
    gate("recent_recall", candidate["recall"] >= 0.45, candidate["recall"], ">=0.45 provisional demo gate")
    gate("recent_false_positive_rate", candidate["fpr"] <= 0.18, candidate["fpr"], "<=0.18 provisional demo gate")
    gate("ranking_vs_rules", candidate["pr_auc"] >= baseline["pr_auc"] - 0.02,
         {"candidate": candidate["pr_auc"], "rules": baseline["pr_auc"]}, "AP regression <=0.02")
    gate("replay_precision", replay["precision"] >= 0.50, replay["precision"], ">=0.50")
    previous_metrics = None
    if previous_artifact:
        # Comparing on data the incumbent has already seen is not a retention test.
        hashes = set(previous_artifact.get("training_event_hashes", []))
        entity_hashes = set(previous_artifact.get("training_entity_hashes", []))
        overlap = sum(_id_hash(r["event_id"]) in hashes or _id_hash(r["entity_id"]) in entity_hashes
                      for part in ("historical_replay", "final_recent") for r in groups[part])
        lineage_known = "training_event_hashes" in previous_artifact and "training_entity_hashes" in previous_artifact
        gate("incumbent_unseen_holdouts", overlap == 0 and lineage_known,
             {"overlap": overlap, "lineage_known": lineage_known}, "0 overlap; recorded training membership")
        if overlap == 0 and lineage_known:
            try:
                previous_metrics = {part: _metric(groups[part], [score_artifact(r["features"], previous_artifact) for r in groups[part]], previous_artifact["threshold"])
                                    for part in ("historical_replay", "final_recent")}
                for part, current in (("historical_replay", replay), ("final_recent", candidate)):
                    old = previous_metrics[part]
                    gate("retention_" + part, current["recall"] >= old["recall"] - 0.05 and current["fpr"] <= old["fpr"] + 0.03,
                         {"candidate_recall": current["recall"], "incumbent_recall": old["recall"], "candidate_fpr": current["fpr"], "incumbent_fpr": old["fpr"]},
                         "recall regression <=0.05, FPR increase <=0.03")
            except (KeyError, ValueError, TypeError, OverflowError):
                gate("incumbent_artifact_valid", False, "Invalid incumbent", "Valid JSON artifact")
    result.update({"artifact": selected, "metrics": {"baseline": baseline, "candidate": candidate,
                   "historical_replay": replay, "validation": validation_metrics,
                   "operational_hybrid": comparisons["final_recent"]["operational_hybrid"],
                   "comparisons": comparisons, "previous": previous_metrics,
                   "selection": {"model": selected_name, "criterion": "validation recall at FPR<=0.10; AP tie-break", "threshold_fit": "validation only"}},
                   "eligible": all(g["passed"] for g in gates),
                   "status": "ready_for_independent_demo_review" if all(g["passed"] for g in gates) else "rejected_by_offline_gates"})
    return result


def drift_summary(reference_rows: list[dict], recent_rows: list[dict]) -> dict:
    """PSI is a review trigger, not evidence of concept drift or a retrain command."""
    import numpy as np
    if min(len(reference_rows), len(recent_rows)) < 30:
        return {"status": "insufficient_support", "reference_count": len(reference_rows), "recent_count": len(recent_rows), "features": [], "max_psi": None}
    results = []
    for name in FEATURE_NAMES:
        ref = np.asarray([_vector(r.get("features", r), [name])[0] for r in reference_rows])
        new = np.asarray([_vector(r.get("features", r), [name])[0] for r in recent_rows])
        middle = np.unique(np.quantile(ref, [0.1, 0.25, 0.5, 0.75, 0.9]))
        if len(middle) == 1:
            middle = np.asarray([middle[0] - 1e-6, middle[0] + 1e-6])
        edges = np.r_[-np.inf, middle, np.inf]
        left, right = np.histogram(ref, edges)[0].astype(float), np.histogram(new, edges)[0].astype(float)
        left, right = (left + 0.5) / (len(ref) + 0.5 * len(left)), (right + 0.5) / (len(new) + 0.5 * len(right))
        psi = float(np.sum((right - left) * np.log(right / left)))
        results.append({"feature": name, "psi": round(psi, 6)})
    results.sort(key=lambda item: item["psi"], reverse=True)
    maximum = results[0]["psi"]
    return {"status": "review_required" if maximum >= 0.25 else "stable", "max_psi": maximum,
            "reference_count": len(reference_rows), "recent_count": len(recent_rows), "features": results,
            "interpretation": "Univariate population shift; not a concept-drift test or bank-calibrated threshold", "automatic_retraining": False}


def run_research(seed: int = SEED, count: int = 1800) -> dict:
    """Reproduce fixed comparisons, ablation and a training-label negative control."""
    import time
    from .synthetic import make_training_rows
    started = time.perf_counter()
    rows = make_training_rows(seed, count)
    cutoff = _iso(parse_time(rows[-1]["label_available_at"]) + timedelta(days=2))
    report = train_candidate(rows, now=cutoff)
    if report["artifact"] is None:
        return report
    prepared, _ = _prepare(rows, parse_time(cutoff))
    groups, _ = _split(prepared, parse_time(cutoff))
    shuffled = [dict(row) for row in groups["train"]]
    labels = [r["label"] for r in shuffled]
    random.Random(seed + 1).shuffle(labels)
    for row, label in zip(shuffled, labels):
        row["label"] = label
    placebo = _fit(shuffled, list(FEATURE_NAMES), "permuted_training_labels")
    validation_scores = [score_artifact(r["features"], placebo) for r in groups["validation"]]
    placebo["threshold"] = _threshold(groups["validation"], validation_scores)
    recent = groups["final_recent"]
    negative = _metric(recent, [score_artifact(r["features"], placebo) for r in recent], placebo["threshold"])
    # Entity-level bootstrap is row-level here because generator emits one/entity.
    import numpy as np
    from sklearn.metrics import average_precision_score
    rng = np.random.default_rng(seed)
    labels = np.asarray([r["label"] for r in recent])
    scores = np.asarray([score_artifact(r["features"], report["artifact"]) for r in recent])
    samples = []
    for _ in range(400):
        positions = rng.integers(0, len(recent), len(recent))
        if len(set(labels[positions])) == 2:
            samples.append(float(average_precision_score(labels[positions], scores[positions])))
    interval = np.quantile(samples, [0.025, 0.975]).tolist()
    report["research"] = {
        "seed": seed, "generated_rows": count, "runtime_seconds": round(time.perf_counter() - started, 3),
        "data": "synthetic-ground-truth only; overlapping legitimate and malicious episodes",
        "mechanism": "Earlier same-entity identity/endpoint/network observations can distinguish suspicious sequences from isolated high-volume administration.",
        "ablation": "pointwise_logistic removes all context; same split, fit policy and validation threshold policy",
        "negative_control": {"method": "Permutation of training labels only; original validation/final labels retained", "metrics": negative,
                             "final_prevalence": round(float(labels.mean()), 6)},
        "candidate_ap_95_percent_bootstrap_interval": [round(v, 6) for v in interval],
        "interval_unit": "independent synthetic episode/entity (one decision per entity), 400 resamples",
        "drift": drift_summary(groups["historical_replay"], recent),
        "reproduce": "python scripts/evaluate.py --seed 41 --count 1800",
        "status": "measured synthetic pipeline experiment; real bank efficacy remains unvalidated",
    }
    return report
