"""Meaningful leakage, governance, inference and adversarial-input regressions."""
from copy import deepcopy
from datetime import timedelta
import json
import math
import unittest

from app.detection import FEATURE_NAMES, detect_event, featurize, parse_time
from app.learning import _prepare, _split, drift_summary, score_artifact, train_candidate
from app.synthetic import make_demo_events, make_training_rows


def event(kind="login_failed", second=0, entity="entity-a", **changes):
    base = {"id": f"{entity}-{second}-{kind}", "entity_id": entity, "asset_id": "node-a",
            "event_type": kind, "source": "identity", "event_time": f"2026-01-01T12:{second // 60:02d}:{second % 60:02d}Z",
            "received_at": f"2026-01-01T12:{second // 60:02d}:{second % 60:02d}Z",
            "src_ip": "192.0.2.1", "dst_ip": "203.0.113.4", "bytes_out": 0,
            "privileged": False, "unusual_process": False, "external": False,
            "criticality": "standard", "synthetic": True}
    base.update(changes)
    return base


class DecisionBoundaryTests(unittest.TestCase):
    def test_future_late_other_entity_and_duplicates_cannot_inflate_history(self):
        current = event("login_success", 100)
        old = event(second=50)
        future = event(second=110)
        late = event(second=55, received_at="2026-01-01T12:02:00Z")
        other = event(second=40, entity="different")
        simultaneous = event(second=100)
        features = featurize(current, [old, old, future, late, other, simultaneous, current])
        self.assertEqual(features["failures_5m"], 1)
        self.assertEqual(features["login_after_failures"], 0)
        self.assertEqual(detect_event(current, [old, future, late, other])["evidence_ids"], [old["id"], current["id"]])

    def test_order_changes_result_and_evidence_never_uses_future(self):
        failures = [event(second=x) for x in (0, 20, 40)]
        success = event("login_success", 60)
        process = event("process_start", 80, source="endpoint", unusual_process=True)
        target = event("network_connection", 100, source="network", external=True, bytes_out=8_000_000)
        result = detect_event(target, failures + [success, process])
        self.assertTrue(result["alert"])
        self.assertIn("CROSS_SOURCE_SEQUENCE", result["reason_codes"])
        before_success = event("process_start", 50, source="endpoint", unusual_process=True)
        self.assertEqual(featurize(target, failures + [success, before_success])["ordered_compromise_sequence"], 0)

    def test_new_entities_and_malformed_optional_bytes_are_finite(self):
        features = featurize(event("network_connection", 0, bytes_out=float("nan"), external=True), [])
        self.assertEqual(set(features), set(FEATURE_NAMES))
        self.assertTrue(all(math.isfinite(v) for v in features.values()))
        self.assertEqual(features["new_external_destination"], 1)
        result = detect_event(event("login_success"), [], {"schema": "not-supported"})
        self.assertIsNone(result["model_score"])
        self.assertIn("MODEL_UNAVAILABLE", result["reason_codes"])
        self.assertFalse(result["alert"])

    def test_generator_is_reproducible_and_no_label_in_feature_input(self):
        self.assertEqual(make_training_rows(11, 40), make_training_rows(11, 40))
        self.assertNotEqual(make_training_rows(11, 40), make_training_rows(12, 40))
        rows = make_training_rows(11, 40)
        self.assertEqual(len({r["entity_id"] for r in rows}), 40)
        self.assertNotIn("label", rows[0]["features"])
        events = make_demo_events(4, 72)
        self.assertEqual(len(events), 72)
        self.assertEqual(len({e["id"] for e in events}), 72)
        self.assertTrue(all(e["synthetic"] is True for e in events))


class LearningGovernanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = make_training_rows(41, 900)
        cls.cutoff = "2026-01-01T00:00:00Z"
        cls.result = train_candidate(cls.rows, now=cls.cutoff)

    def test_json_inference_roundtrip_and_input_sensitivity(self):
        artifact = self.result["artifact"]
        self.assertIsNotNone(artifact)
        loaded = json.loads(json.dumps(artifact, allow_nan=False))
        scores = [score_artifact(row["features"], loaded) for row in self.rows[:50]]
        self.assertGreater(max(scores) - min(scores), 0.2)
        self.assertTrue(all(0 <= score <= 1 for score in scores))
        for row in self.rows[:5]:
            self.assertEqual(score_artifact(row["features"], artifact), score_artifact(row["features"], loaded))
        malicious_artifact = deepcopy(artifact)
        malicious_artifact["scales"][0] = 0
        with self.assertRaises(ValueError):
            score_artifact(self.rows[0]["features"], malicious_artifact)

    def test_production_always_requires_separate_validation(self):
        self.assertFalse(self.result["production_eligible"])
        self.assertEqual(self.result["deployment_scope"], "demo_only")
        self.assertIn("synthetic_training_or_evaluation", self.result["production_blockers"])
        small = train_candidate(self.rows[:35], now=self.cutoff)
        self.assertFalse(small["eligible"])
        self.assertIsNone(small["artifact"])
        self.assertTrue(any(not g["passed"] for g in small["gates"]))

    def test_training_threshold_unchanged_by_final_label_permutation(self):
        changed = deepcopy(self.rows)
        final_ids = set(self.result["split_manifest"]["cohorts"]["final_recent"]["event_ids"])
        for row in changed:
            if row["event_id"] in final_ids:
                row["label"] = 1 - row["label"]
        altered = train_candidate(changed, now=self.cutoff)
        self.assertEqual(self.result["artifact"], altered["artifact"])
        self.assertNotEqual(self.result["metrics"]["candidate"]["pr_auc"], altered["metrics"]["candidate"]["pr_auc"])

    def test_split_enforces_entity_time_purge_and_label_maturity(self):
        rows = deepcopy(self.rows)
        rows[0]["entity_id"] = rows[-1]["entity_id"]
        rows[1]["label_available_at"] = "2025-12-01T00:00:00Z"
        now = parse_time(self.cutoff)
        prepared, _ = _prepare(rows, now)
        groups, manifest = _split(prepared, now)
        self.assertEqual(manifest["purged"]["boundary_entities"], 1)
        self.assertNotIn(rows[1]["event_id"], {row["event_id"] for row in groups["train"]})
        sets = [{r["entity_id"] for r in part} for part in groups.values()]
        for i, left in enumerate(sets):
            for right in sets[i + 1:]:
                self.assertFalse(left & right)
        for index, name in enumerate(("train", "validation", "historical_replay")):
            end = parse_time(manifest["time_cutoffs"][index]) - timedelta(seconds=900)
            self.assertTrue(all(parse_time(row["label_available_at"]) <= end for row in groups[name]))

    def test_future_labels_and_conflicts_are_not_silently_negative(self):
        rows = deepcopy(self.rows[:40])
        rows[0]["label_available_at"] = "2030-01-01T00:00:00Z"
        conflict = deepcopy(rows[1])
        conflict["label"] = 1 - conflict["label"]
        rows += [conflict, deepcopy(rows[2])]
        prepared, counts = _prepare(rows, parse_time(self.cutoff))
        self.assertEqual(counts["unmatured"], 1)
        self.assertEqual(counts["conflicting_duplicates"], 1)
        self.assertEqual(counts["duplicates"], 1)
        ids = {row["event_id"] for row in prepared}
        self.assertNotIn(rows[0]["event_id"], ids)
        self.assertNotIn(rows[1]["event_id"], ids)

    def test_incumbent_seen_holdout_blocks_eligibility(self):
        old = deepcopy(self.result["artifact"])
        import hashlib
        final_id = self.result["split_manifest"]["cohorts"]["final_recent"]["event_ids"][0]
        old["training_event_hashes"].append(hashlib.sha256(final_id.encode()).hexdigest())
        next_result = train_candidate(self.rows, previous_artifact=old, now=self.cutoff)
        self.assertFalse(next_result["eligible"])
        self.assertFalse(next(g for g in next_result["gates"] if g["name"] == "incumbent_unseen_holdouts")["passed"])

    def test_model_threshold_controls_alert_separately_from_risk(self):
        artifact = deepcopy(self.result["artifact"])
        artifact["weights"] = [0.0] * len(artifact["weights"])
        artifact["intercept"] = 1.0
        artifact["threshold"] = 0.9
        output = detect_event(event("login_success"), [], artifact)
        self.assertGreater(output["score"], 70)
        self.assertFalse(output["model_alert"])
        self.assertFalse(output["alert"])
        artifact["threshold"] = 0.7
        self.assertTrue(detect_event(event("login_success"), [], artifact)["alert"])
        artifact["threshold"] = float("nan")
        invalid = detect_event(event("login_success"), [], artifact)
        self.assertFalse(invalid["alert"])
        self.assertIsNone(invalid["model_score"])

    def test_drift_has_minimum_support_and_is_not_retrain_instruction(self):
        self.assertEqual(drift_summary(self.rows[:5], self.rows[-5:])["status"], "insufficient_support")
        same = drift_summary(self.rows[:80], self.rows[:80])
        self.assertEqual(same["max_psi"], 0)
        changed = deepcopy(self.rows[:80])
        for row in changed:
            row["features"]["log_bytes_out"] += 100
        result = drift_summary(self.rows[:80], changed)
        self.assertEqual(result["status"], "review_required")
        self.assertFalse(result["automatic_retraining"])


if __name__ == "__main__":
    unittest.main()
