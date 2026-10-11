"""Reproducible HTTP benchmark training and reviewed-feedback replay.

CSIC has no reliable event timestamps or entities. This is an explicitly named
supervised, feature-group-disjoint repartition, NOT its original anomaly protocol
and NOT a forward-time or cross-bank generalisation claim.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from .http_detection import FEATURE_NAMES, MODEL_FEATURE_NAMES, SCHEMA, features, rule_reasons, score, validate_artifact
from .store import canonical, digest, utcnow


def partition(group):
    bucket = int(hashlib.sha256(("http-v1:" + group).encode()).hexdigest()[:8], 16) % 100
    return "train" if bucket < 70 else "validation" if bucket < 85 else "test"


def feature_group(f):
    return digest({name: f[name] for name in MODEL_FEATURE_NAMES})


def parse_csic(path):
    text = Path(path).read_text(encoding="latin1").replace("\r\n", "\n")
    starts = list(re.finditer(r"(?m)^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|PATCH) (\S+) HTTP/1\.[01]\s*$", text))
    if not starts:
        raise ValueError("CSIC_NO_REQUESTS")
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        tail = text[match.end():end].lstrip("\n")
        parts = tail.split("\n\n", 1)
        body = parts[1].strip("\n") if len(parts) == 2 else ""
        yield index + 1, match[1], match[2], body


def prepare_public(source_dir, destination):
    source_dir, destination = Path(source_dir), Path(destination)
    manifest = json.loads((source_dir / "manifest.json").read_text(encoding="utf8"))
    rows, conflict, counts = {}, set(), Counter()
    for item in manifest["files"]:
        path = source_dir / item["name"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("PUBLIC_SOURCE_HASH_MISMATCH")
        label = int(item["name"] == "anomalousTrafficTest.txt")
        for index, method, target, body in parse_csic(path):
            counts["raw_requests"] += 1
            try:
                f = features(method, target, body)
            except ValueError:
                counts["oversize_or_invalid"] += 1
                continue
            # Deduplicate the actual representation used by the model. Equivalent
            # vectors cannot straddle cohorts, even with different cookies/URLs.
            group = feature_group(f)
            if group in rows:
                counts["duplicate_feature_vectors"] += 1
                if rows[group]["label"] != label:
                    conflict.add(group)
                continue
            rows[group] = {"id": "CSIC-" + group, "group": group, "features": f, "label": label,
                "split": partition(group), "source": "public_lab_capture", "synthetic": True,
                "provenance": "CSIC2010:" + item["name"] + ":" + str(index),
                "label_semantics": "normal_vs_anomalous", "feature_schema": SCHEMA}
    for key in conflict:
        rows.pop(key, None)
    counts["conflicting_feature_groups_removed"] = len(conflict)
    ordered = sorted(rows.values(), key=lambda r: r["id"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(canonical(r) for r in ordered) + "\n"
    destination.write_bytes(content.encode("utf8"))
    summary = {"created_at": utcnow(), "source_manifest": manifest, "quality": dict(counts),
        "rows": len(ordered), "positives": sum(r["label"] for r in ordered),
        "feature_schema": SCHEMA, "dataset_sha256": hashlib.sha256(content.encode()).hexdigest(),
        "protocol": "supervised_repartition/sha256_feature_groups/70-15-15",
        "raw_data_stored_in_features": False, "split_counts": dict(Counter(r["split"] for r in ordered)),
        "limitations": ["Automatically generated HTTP requests from a 2010 e-commerce lab; not bank production logs.",
            "Anomalous includes unintentional invalid requests, not just malicious activity.",
            "Same benchmark reused for future regressions; not fresh independent evidence.",
            "Feature grouping removes identical-vector leakage; does not prove unseen attack-family generalisation."]}
    destination.with_suffix(".manifest.json").write_text(json.dumps(summary, indent=2), encoding="utf8")
    return summary


def load_public(path):
    path = Path(path)
    manifest = json.loads(path.with_suffix(".manifest.json").read_text(encoding="utf8"))
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != manifest["dataset_sha256"]:
        raise ValueError("HTTP_DATASET_INTEGRITY_FAILED")
    return [json.loads(line) for line in content.splitlines() if line.strip()], manifest


def metrics(truth, values, threshold):
    from sklearn.metrics import average_precision_score
    tp = fp = tn = fn = 0
    for y, p in zip(truth, values):
        if p >= threshold:
            tp += y == 1
            fp += y == 0
        else:
            tn += y == 0
            fn += y == 1
    return {"support": len(truth), "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "precision": tp / max(1, tp + fp), "recall": tp / max(1, tp + fn),
        "fpr": fp / max(1, fp + tn), "accuracy": (tp + tn) / max(1, len(truth)),
        "average_precision": float(average_precision_score(truth, values)) if sum(truth) and sum(truth) < len(truth) else None}


def choose_threshold(truth, values, fpr_limit, precision_min=0, minimum_alerts=1):
    # O(n log n), avoid quadratic threshold search on a real dataset.
    pos, neg = sum(truth), len(truth) - sum(truth)
    tp = fp = 0
    best, selected = (-1, -1, -1), 1.00000001
    ordered = sorted(zip(values, truth), reverse=True)
    for i, (value, y) in enumerate(ordered):
        tp += y == 1
        fp += y == 0
        if i + 1 < len(ordered) and ordered[i + 1][0] == value:
            continue
        precision = tp / max(1, tp + fp)
        if fp / max(1, neg) <= fpr_limit and precision >= precision_min and tp + fp >= minimum_alerts:
            utility = (tp / max(1, pos), precision, value)
            if utility > best:
                best, selected = utility, float(value)
    return selected


def feedback_rows(base, feedback):
    """Freeze public holdouts and whole lab runs; never train a holdout vector.

    Independent reviewed revisions replace earlier labels. We preserve both
    human action and outcome as metadata; neither is a feature or an auto-label.
    """
    base_groups = {r["group"]: r["split"] for r in base}
    by_group = {}
    for row in sorted(feedback, key=lambda r: (r["label_available_at"], r["id"])):
        if row.get("review_status") != "approved" or row.get("created_by") == row.get("reviewed_by"):
            raise ValueError("HTTP_UNREVIEWED_FEEDBACK")
        if row["label"] not in (0, 1) or set(row["features"]) != set(FEATURE_NAMES):
            raise ValueError("HTTP_INVALID_FEEDBACK")
        group = feature_group(row["features"])
        if group in base_groups and base_groups[group] != "train":
            continue  # reserved public evaluation stays untouched
        by_group.setdefault(group, []).append(row)
    admitted, conflicts = [], 0
    for group, revisions in by_group.items():
        labels = {r["label"] for r in revisions}
        if len(labels) != 1:
            conflicts += 1
            continue
        row = revisions[-1]
        # Group by run AND purge feature overlap: no synthetic fake timestamps.
        splits = {partition(r["group_id"]) for r in revisions}
        if len(splits) > 1:
            continue
        split = splits.pop()
        if group in base_groups and split != "train":
            continue
        admitted.append({**row, "group": group, "split": split, "source": "reviewed_local_lab"})
    return admitted, conflicts


def train_http(base, feedback=(), parent=None):
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    reviewed, conflicts = feedback_rows(base, feedback)
    replaced = {r["group"] for r in reviewed}
    rows = [r for r in base if r["group"] not in replaced] + reviewed
    groups = {name: [r for r in rows if r["split"] == name] for name in ("train", "validation", "test")}
    for name, cohort in groups.items():
        if len(cohort) < (200 if name == "train" else 60) or min(sum(r["label"] for r in cohort), sum(1-r["label"] for r in cohort)) < 12:
            raise ValueError("HTTP_INSUFFICIENT_CLASS_SUPPORT_" + name)
    x = {name: np.asarray([[r["features"][k] for k in MODEL_FEATURE_NAMES] for r in group], dtype=np.float64) for name, group in groups.items()}
    y = {name: [r["label"] for r in group] for name, group in groups.items()}
    model = RandomForestClassifier(n_estimators=64, max_depth=12, min_samples_leaf=3,
        max_features=0.75, class_weight="balanced_subsample", random_state=41, n_jobs=2)
    model.fit(x["train"], y["train"])
    val = model.predict_proba(x["validation"])[:, 1].tolist()
    alert = choose_threshold(y["validation"], val, .03)
    block = max(alert, choose_threshold(y["validation"], val, .002, .98, 12))
    trees = []
    for estimator in model.estimators_:
        t = estimator.tree_
        probabilities = t.value[:, 0, 1] / t.value[:, 0, :].sum(axis=1)
        trees.append({"left": t.children_left.tolist(), "right": t.children_right.tolist(),
            "feature": t.feature.tolist(), "threshold": t.threshold.tolist(), "probability": probabilities.tolist()})
    artifact = {"schema": SCHEMA, "type": "random_forest", "feature_names": list(MODEL_FEATURE_NAMES),
        "trees": trees, "alert_threshold": alert, "block_threshold": block, "parent_version": parent,
        "training_hash": digest(sorted((r["id"], r["label"]) for r in groups["train"])),
        "scope": "loopback_lab_only", "score_semantics": "uncalibrated_anomaly_rank", "production_eligible": False}
    artifact["version"] = "http-rf-" + digest(artifact)[:12]
    validate_artifact(artifact)
    # sklearn compares float32 input internally; preserve parity in portable JSON.
    for index in range(min(100, len(groups["validation"]))):
        actual = score(groups["validation"][index]["features"], artifact)
        if abs(actual - val[index]) > 1e-7:
            raise ValueError("HTTP_INFERENCE_PARITY_FAILED")
    test = model.predict_proba(x["test"])[:, 1].tolist()
    baseline = [float(bool(rule_reasons(r["features"]))) for r in groups["test"]]
    report = {"created_at": utcnow(), "version": artifact["version"],
        "protocol": "supervised_feature_group_disjoint/70-15-15", "threshold_source": "validation_only",
        "seed": 41, "production_eligible": False, "scope": "loopback_lab_only",
        "cohorts": {name: {"rows": len(group), "positive": sum(r["label"] for r in group),
            "membership_hash": digest(sorted(r["id"] for r in group))} for name, group in groups.items()},
        "candidate": metrics(y["test"], test, alert), "rules": metrics(y["test"], baseline, .5),
        "hybrid": metrics(y["test"], [max(float(s >= alert), r) for s, r in zip(test, baseline)], .5),
        "blocking": metrics(y["test"], test, block), "validation": metrics(y["validation"], val, alert),
        "alert_threshold": alert, "block_threshold": block,
        "model_only_true_positives": sum(yy == 1 and s >= alert and not r for yy, s, r in zip(y["test"], test, baseline)),
        "model_only_false_positives": sum(yy == 0 and s >= alert and not r for yy, s, r in zip(y["test"], test, baseline)),
        "feedback": {"reviewed_available": len(feedback), "admitted": len(reviewed), "conflicting_groups": conflicts,
            "train": sum(r["split"] == "train" for r in reviewed), "reserved_holdout": sum(r["split"] != "train" for r in reviewed)},
        "feature_importance": sorted(zip(MODEL_FEATURE_NAMES, model.feature_importances_.tolist()), key=lambda v: -v[1])[:12],
        "limitations": ["2010 generated lab benchmark, not bank traffic; positive means anomalous.",
            "No claim of universal attack coverage or calibrated breach probability.",
            "Repeated benchmark is regression evidence. Validate on new real deployments separately."]}
    report["eligible"] = report["candidate"]["recall"] >= .5 and report["candidate"]["fpr"] <= .06
    report["auto_block_eligible"] = report["eligible"] and report["blocking"]["precision"] >= .98 and report["blocking"]["fpr"] <= .005 and report["blocking"]["tp"] >= 12
    return artifact, report
