"""Auditable application use cases. No network, shell or live response adapters."""
from datetime import datetime, timedelta, timezone
import threading
from fastapi import HTTPException
from .detection import detect_event, FEATURE_NAMES
from .security import clean_note
from .store import digest, new_id, parse_time, utcnow


ASSETS = [
    {"id": f"bank-node-{i:02d}", "name": name, "criticality": criticality, "type": kind}
    for i, (name, criticality, kind) in enumerate([
        ("Core ledger / primary", "critical", "server"), ("Treasury workstation", "high", "endpoint"),
        ("Branch operations 01", "standard", "endpoint"), ("Payment gateway", "critical", "server"),
        ("SOC workstation 01", "high", "endpoint"), ("Branch operations 02", "standard", "endpoint"),
        ("Identity directory", "critical", "server"), ("Card operations 01", "high", "endpoint"),
        ("Branch operations 03", "standard", "endpoint"), ("Mobile banking API", "critical", "server"),
        ("Risk workstation 01", "high", "endpoint"), ("Branch operations 04", "standard", "endpoint"),
        ("Reporting replica", "high", "server"), ("Treasury workstation 02", "high", "endpoint"),
        ("Branch operations 05", "standard", "endpoint"), ("ATM switch", "critical", "server"),
        ("SOC workstation 02", "high", "endpoint"), ("Branch operations 06", "standard", "endpoint"),
        ("Authentication gateway", "critical", "server"), ("Card operations 02", "high", "endpoint"),
        ("Branch operations 07", "standard", "endpoint"), ("Backup management", "high", "server"),
        ("Risk workstation 02", "high", "endpoint"), ("Branch operations 08", "standard", "endpoint"),
    ])
]


class SOCService:
    def __init__(self, settings, store, security):
        self.settings, self.store, self.security = settings, store, security
        self.training_lock = threading.Lock()
        with store.transaction() as conn:
            self._bind_environment(conn)
            if not store.get("settings", "policy", conn):
                store.put("settings", {"id": "policy", "version": 1, "mode": "simulation", "dry_run": True,
                    "kill_switch": True, "requires_approval": True, "manual_retraining_only": True,
                    "approval_ttl_minutes": 15}, conn)
                # The demo inventory is never installed as a bank's real CMDB.
                if settings.mode == "demo":
                    for asset in ASSETS:
                        store.put("assets", {**asset, "synthetic": True}, conn)
                store.put("models", {"id": "MODEL-RULES-V1", "version": "rules-1.0", "status": "champion",
                    "created_at": utcnow(), "artifact": None, "artifact_hash": digest(None), "metrics": {}, "gates": [],
                    "eligible": True, "synthetic": False, "trained_by": "system", "approved_by": "system",
                    "production_eligible": False, "deployment_scope": "local_reference"}, conn)
                store.audit("system", "system.initialized", "AI-SOC", {"mode": settings.mode, "live_execution": False}, conn)
            policy = store.get("settings", "policy", conn)
            if not policy.get("manual_retraining_only") or "learning_enabled" in policy:
                policy["manual_retraining_only"] = True
                policy.pop("learning_enabled", None)
                policy.pop("learning_min_new_labels", None)
                store.put("settings", policy, conn)
                store.audit("system", "learning.manual_control_enforced", "learning", {"automatic_training": False}, conn)

    def _bind_environment(self, conn):
        """A mode switch must never carry demo state or sessions into a pilot."""
        marker = self.store.get("settings", "environment", conn)
        if marker and marker.get("mode") != self.settings.mode:
            raise ValueError("SOC data directory belongs to a different mode; choose a separate SOC_DATA_DIR")
        if self.settings.mode == "pilot":
            # Also inspect rows for a legacy database with no mode marker. An
            # active JSON classifier can only be demo-approved in this release.
            # Inactive candidates trained in a marked pilot may remain stored.
            for kind in ("assets", "events", "incidents", "labels", "training_rows", "snapshots", "models"):
                for item in self.store.all(kind, conn):
                    active_local_model = kind == "models" and item.get("artifact") is not None and (marker is None or item.get("status") == "champion")
                    if item.get("synthetic") is True or active_local_model:
                        raise ValueError("Pilot cannot open demo, synthetic, or unapproved active model state; choose a clean SOC_DATA_DIR")
            has_legacy_state = any(self.store.all(kind, conn) for kind in ("settings", "assets", "events", "models", "training_rows"))
            has_sessions = conn.execute("SELECT 1 FROM sessions LIMIT 1").fetchone() is not None
            if marker is None and (has_legacy_state or has_sessions):
                # Provenance is unknowable for an unmarked pre-migration DB;
                # never infer environment trust from missing synthetic flags.
                raise ValueError("Unmarked existing data requires an explicit reviewed migration; use a fresh pilot SOC_DATA_DIR")
        if marker is None:
            self.store.put("settings", {"id": "environment", "mode": self.settings.mode,
                "bound_at": utcnow(), "schema_version": 1}, conn)
            self.store.audit("system", "environment.bound", "environment", {"mode": self.settings.mode}, conn)

    def seed(self):
        if self.settings.mode != "demo" or not self.settings.auto_seed or self.store.all("events"):
            return
        from .synthetic import make_demo_events, make_training_rows
        with self.store.transaction() as conn:
            if self.store.all("events", conn):
                return
            self.ingest(make_demo_events(), "demo.generator", conn=conn, synthetic=True)
            for row in make_training_rows():
                # Identities in learning exports are project-keyed, not raw account names.
                row["entity_id"] = self.security.pseudonym(row["entity_id"])
                self.store.put("training_rows", {"id": row["event_id"], **row}, conn)
            self.store.audit("demo.generator", "dataset.synthetic_seeded", "dataset", {"rows": 900, "real_bank_data": False}, conn)

    def required(self, kind, identifier, conn=None):
        obj = self.store.get(kind, identifier, conn)
        if not obj:
            raise HTTPException(404, "NOT_FOUND")
        return obj

    def champion(self, conn=None):
        for model in self.store.all("models", conn):
            if model["status"] == "champion":
                return model
        raise RuntimeError("No champion model")

    def policy(self, conn=None):
        return self.required("settings", "policy", conn)

    def ingest(self, events, actor, conn=None, synthetic=False):
        if conn is None:
            with self.store.transaction() as transaction:
                return self.ingest(events, actor, transaction, synthetic)
        history = self.store.all("events", conn)
        incidents = self.store.all("incidents", conn)
        champion = self.champion(conn)
        if digest(champion.get("artifact")) != champion["artifact_hash"]:
            raise HTTPException(503, "MODEL_INTEGRITY_FAILED")
        accepted = duplicates = opened = 0
        ids = []
        for raw in events:
            asset = self.store.get("assets", raw["asset_id"], conn)
            if not asset:
                raise HTTPException(422, "UNKNOWN_ASSET")
            # Use authoritative CMDB criticality; callers cannot downgrade a target.
            data = {**raw, "synthetic": synthetic, "criticality": asset["criticality"]}
            data["entity_id"] = self.security.pseudonym(raw["entity_id"])
            data["payload_hash"] = digest({k: v for k, v in data.items() if k not in {"received_at"}})
            existing = self.store.get("events", raw["id"], conn)
            if existing:
                if existing["payload_hash"] != data["payload_hash"]:
                    raise HTTPException(409, "EVENT_ID_CONFLICT")
                duplicates += 1
                continue
            data["received_at"] = raw.get("received_at", utcnow()) if synthetic else utcnow()
            data["collector"] = actor
            data["schema_version"] = "soc-event-v1"
            decision = detect_event(data, history, champion.get("artifact"))
            data.update(decision)
            data["model_version"] = champion["version"]
            data["decision_time"] = data["received_at"]
            self.store.put("events", data, conn)
            history.append(data)
            accepted += 1
            ids.append(data["id"])
            if decision.get("alert", decision["rule_score"] >= 40):
                # Bounded case correlation, same pseudonymous identity AND asset.
                matching = [i for i in incidents if i["entity_id"] == data["entity_id"]
                    and i["asset_id"] == data["asset_id"] and i["status"] != "closed"
                    and 0 <= (parse_time(data["event_time"]) - parse_time(i["last_event_time"])).total_seconds() <= 1800]
                incident = matching[-1] if matching else {"id": new_id("INC"), "title_code": "security_signal",
                    "asset_id": data["asset_id"], "entity_id": data["entity_id"], "severity": data["severity"],
                    "score": 0, "status": "open", "created_at": data["received_at"], "event_ids": [],
                    "reason_codes": [], "mitre": [], "owner": None, "synthetic": synthetic}
                if not matching:
                    incidents.append(incident)
                    opened += 1
                incident["event_ids"] = list(dict.fromkeys(incident["event_ids"] + data["evidence_ids"]))
                incident["reason_codes"] = list(dict.fromkeys(incident["reason_codes"] + data["reason_codes"]))
                incident["mitre"] = sorted(set(incident["mitre"] + data["mitre"]))
                incident["ip_addresses"] = sorted(set(incident.get("ip_addresses", []) + [data["src_ip"], data["dst_ip"]]))
                if data["score"] >= incident["score"]:
                    incident.update(score=data["score"], severity=data["severity"], features=data["features"],
                        model_version=data["model_version"], decision_event_id=data["id"])
                incident.update(updated_at=data["received_at"], last_event_time=data["event_time"])
                codes = incident["reason_codes"]
                incident["title_code"] = "credential_compromise" if "CROSS_SOURCE_SEQUENCE" in codes else "exfiltration" if "EXTERNAL_DATA_TRANSFER" in codes else "privilege_abuse" if "PRIVILEGE_AFTER_LOGIN" in codes else "suspicious_process" if "UNUSUAL_PROCESS" in codes else "authentication_anomaly" if "AUTH_FAILURE_BURST" in codes else "security_signal"
                self.store.put("incidents", incident, conn)
        self.store.audit(actor, "telemetry.ingested", "telemetry", {"accepted": accepted, "duplicates": duplicates,
            "incidents_opened": opened, "synthetic": synthetic, "event_ids_hash": digest(ids)}, conn)
        return {"accepted": accepted, "duplicates": duplicates, "incidents_opened": opened}

    def replay(self, scenario, actor):
        # Safe emulation is telemetry only; no processes, network attacks or bank calls.
        at = datetime.now(timezone.utc) - timedelta(minutes=4)
        identifier = new_id("REPLAY")
        kinds = ["login_success", "network_connection"] if scenario == "benign" else ["login_failed"] * 5 + ["login_success", "process_start", "privilege_change", "network_connection", "payment_access"]
        events = []
        for n, kind in enumerate(kinds):
            ts = (at + timedelta(seconds=n * 20)).isoformat().replace("+00:00", "Z")
            events.append({"id": f"{identifier}-{n:02d}", "event_type": kind,
                "source": {"login_failed": "identity", "login_success": "identity", "process_start": "endpoint", "privilege_change": "identity", "network_connection": "network", "payment_access": "core_banking"}[kind],
                "event_time": ts, "received_at": ts, "asset_id": "bank-node-02",
                "entity_id": identifier, "src_ip": "192.0.2.24", "dst_ip": "203.0.113.81",
                "bytes_out": 35000000 if kind == "network_connection" and scenario != "benign" else 1400,
                "privileged": scenario != "benign", "unusual_process": kind == "process_start" and scenario != "benign",
                "external": kind == "network_connection", "synthetic": True})
        if scenario == "exfiltration":
            events = [e for e in events if e["event_type"] in {"process_start", "network_connection"}]
        result = self.ingest(events, actor, synthetic=True)
        if scenario == "mixed":
            benign = self.replay("benign", actor)
            result = {key: value + benign[key] for key, value in result.items()}
        return result

    def submit_label(self, incident_id, label, reason, user):
        with self.store.transaction() as conn:
            incident = self.required("incidents", incident_id, conn)
            if any(l["incident_id"] == incident_id and l["status"] == "pending" for l in self.store.all("labels", conn)):
                raise HTTPException(409, "LABEL_REVIEW_PENDING")
            event = self.required("events", incident["decision_event_id"], conn)
            item = {"id": new_id("LBL"), "incident_id": incident_id, "event_id": event["id"], "label": label,
                "status": "pending", "reason": clean_note(reason), "created_by": user["username"], "created_at": utcnow(),
                "reviewed_by": None, "features_hash": digest(event["features"]), "synthetic": event["synthetic"]}
            self.store.put("labels", item, conn)
            self.store.audit(user["username"], "label.proposed", item["id"], {"incident_id": incident_id, "label": label, "features_hash": item["features_hash"]}, conn)
            return item

    def review_label(self, identifier, decision, reason, user):
        with self.store.transaction() as conn:
            label = self.required("labels", identifier, conn)
            if label["created_by"] == user["username"]:
                raise HTTPException(403, "SELF_APPROVAL_FORBIDDEN")
            if label["status"] != "pending":
                raise HTTPException(409, "LABEL_ALREADY_REVIEWED")
            if label["label"] == "uncertain" and decision == "approve":
                raise HTTPException(422, "UNCERTAIN_NOT_TRAINABLE")
            label.update(status="approved" if decision == "approve" else "rejected", reviewed_by=user["username"],
                reviewed_at=utcnow(), review_reason=clean_note(reason))
            if decision == "approve":
                event = self.required("events", label["event_id"], conn)
                if digest(event["features"]) != label["features_hash"]:
                    raise HTTPException(409, "FEATURE_SNAPSHOT_CHANGED")
                previous_row = self.store.get("training_rows", event["id"], conn)
                if previous_row and previous_row["label"] != int(label["label"] == "malicious"):
                    for model in self.store.all("models", conn):
                        snapshot = self.store.get("snapshots", model.get("dataset_snapshot_id", ""), conn)
                        if snapshot and any(r["event_id"] == event["id"] for r in snapshot["rows"]):
                            model["data_review_required"] = True
                            model["affected_label_ids"] = list(dict.fromkeys(model.get("affected_label_ids", []) + [label["id"]]))
                            self.store.put("models", model, conn)
                            self.store.audit(user["username"], "model.label_revision_detected", model["id"],
                                {"label_id": label["id"], "automatic_rollback": False}, conn)
                # Label only the inspected decision, never every raw event in a case.
                for old in self.store.all("labels", conn):
                    if old["event_id"] == label["event_id"] and old["status"] == "approved":
                        old["status"] = "superseded"
                        self.store.put("labels", old, conn)
                self.store.put("training_rows", {"id": event["id"], "event_id": event["id"], "features": event["features"],
                    "label": int(label["label"] == "malicious"), "event_time": event["event_time"],
                    "observed_at": event["received_at"], "label_available_at": label["reviewed_at"],
                    "entity_id": event["entity_id"], "synthetic": event["synthetic"], "provenance": "independently-reviewed",
                    "label_id": label["id"], "reviewed_by": user["username"], "created_by": label["created_by"]}, conn)
            self.store.put("labels", label, conn)
            self.store.audit(user["username"], "label.reviewed", identifier, {"decision": decision, "label": label["label"], "reason": clean_note(reason)}, conn)
            return label

    def train(self, actor, expected_hash):
        if not self.training_lock.acquire(blocking=False):
            raise HTTPException(409, "TRAINING_ALREADY_RUNNING")
        run_id = new_id("RUN")
        try:
            from .learning import train_candidate
            with self.store.transaction() as conn:
                rows = self.store.all("training_rows", conn)
                fingerprint = digest(sorted(rows, key=lambda r: r["event_id"]))
                if fingerprint != expected_hash:
                    raise HTTPException(409, "DATASET_CHANGED_REVIEW_AGAIN")
                if any(m.get("dataset_hash") == fingerprint for m in self.store.all("models", conn)):
                    raise HTTPException(409, "DATASET_UNCHANGED")
                previous = self.champion(conn)
                if digest(previous.get("artifact")) != previous["artifact_hash"]:
                    raise HTTPException(503, "MODEL_INTEGRITY_FAILED")
                snapshot_id = new_id("DS")
                self.store.put("snapshots", {"id": snapshot_id, "created_at": utcnow(), "hash": fingerprint, "rows": rows,
                    "feature_names": list(FEATURE_NAMES), "synthetic": any(r["synthetic"] for r in rows)}, conn)
                run = {"id": run_id, "status": "running", "created_at": utcnow(), "actor": actor, "snapshot_id": snapshot_id}
                self.store.put("runs", run, conn)
                self.store.audit(actor, "training.started", run_id, {"dataset_hash": fingerprint, "snapshot_id": snapshot_id, "rows": len(rows)}, conn)
            result = train_candidate(rows, previous.get("artifact"))
            with self.store.transaction() as conn:
                model = {"id": new_id("MODEL"), "version": f"context-{len(self.store.all('models', conn))}.0",
                    "status": "challenger", "created_at": utcnow(), "trained_by": actor, "approved_by": None,
                    "synthetic": any(r["synthetic"] for r in rows), "dataset_hash": fingerprint,
                    "dataset_snapshot_id": snapshot_id, **result}
                model["evaluation_status"] = result.get("status")
                model["status"] = "challenger"
                model["trained_against_model_id"] = previous["id"]
                model["artifact_hash"] = digest(model.get("artifact"))
                model["production_eligible"] = False  # Requires bank validation even with non-synthetic data.
                self.store.put("models", model, conn)
                run.update(status="completed", model_id=model["id"], completed_at=utcnow())
                self.store.put("runs", run, conn)
                self.store.audit(actor, "training.completed", model["id"], {"run_id": run_id, "eligible": model["eligible"],
                    "artifact_hash": model["artifact_hash"], "dataset_hash": fingerprint}, conn)
            return self.public_model(model)
        except BaseException as exc:
            with self.store.transaction() as conn:
                run = self.store.get("runs", run_id, conn)
                if run:
                    run.update(status="failed", completed_at=utcnow(), error_code="TRAINING_FAILED")
                    self.store.put("runs", run, conn)
                    self.store.audit(actor, "training.failed", run_id, {"error_type": type(exc).__name__}, conn)
            raise
        finally:
            self.training_lock.release()

    @staticmethod
    def public_model(model):
        return {k: v for k, v in model.items() if k != "artifact"}

    def promote(self, identifier, reason, user, rollback=False):
        with self.store.transaction() as conn:
            model = self.required("models", identifier, conn)
            current = self.champion(conn)
            if model["id"] == current["id"]:
                raise HTTPException(409, "MODEL_ALREADY_ACTIVE")
            if rollback:
                if model["status"] != "retired":
                    raise HTTPException(409, "ROLLBACK_REQUIRES_PREVIOUS_CHAMPION")
                if model.get("data_review_required"):
                    raise HTTPException(409, "TRAINING_LABELS_CHANGED")
            else:
                if model["trained_by"] == user["username"]:
                    raise HTTPException(403, "SELF_APPROVAL_FORBIDDEN")
                if model["status"] != "challenger" or not model["eligible"]:
                    raise HTTPException(409, "MODEL_GATES_FAILED")
                if self.settings.mode != "demo":
                    raise HTTPException(403, "BANK_VALIDATION_REQUIRED")
                if model.get("trained_against_model_id") != current["id"]:
                    raise HTTPException(409, "CHAMPION_CHANGED_REEVALUATE")
                snapshot = self.required("snapshots", model["dataset_snapshot_id"], conn)
                current_rows = {r["event_id"]: r for r in self.store.all("training_rows", conn)}
                if any(digest(r) != digest(current_rows.get(r["event_id"])) for r in snapshot["rows"]):
                    raise HTTPException(409, "TRAINING_LABELS_CHANGED")
            if digest(model.get("artifact")) != model["artifact_hash"]:
                raise HTTPException(409, "MODEL_INTEGRITY_FAILED")
            current["status"] = "retired"
            model.update(status="champion", approved_by=user["username"], promoted_at=utcnow())
            self.store.put("models", current, conn)
            self.store.put("models", model, conn)
            self.store.audit(user["username"], "model.rolled_back" if rollback else "model.promoted", identifier,
                {"previous": current["id"], "reason": clean_note(reason), "scope": "local_only"}, conn)
            return self.public_model(model)

    @staticmethod
    def action_binding(action):
        return digest({k: action[k] for k in ("id", "incident_id", "target", "kind", "scope", "policy_version", "expires_at")})

    def propose_action(self, incident_id, kind, reason, user):
        with self.store.transaction() as conn:
            incident = self.required("incidents", incident_id, conn)
            asset = self.required("assets", incident["asset_id"], conn)
            if asset["criticality"] == "critical":
                raise HTTPException(403, "CRITICAL_ASSET_MANUAL_RUNBOOK")
            if incident["status"] == "closed":
                raise HTTPException(409, "INCIDENT_CLOSED")
            if any(a["incident_id"] == incident_id and a["kind"] == kind and a["status"] in {"awaiting_approval", "approved", "executed"} for a in self.store.all("actions", conn)):
                raise HTTPException(409, "ACTION_ALREADY_PENDING")
            policy = self.policy(conn)
            action = {"id": new_id("ACT"), "incident_id": incident_id, "target": asset["id"], "kind": kind,
                "status": "awaiting_approval", "requested_by": user["username"], "approved_by": None,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=policy["approval_ttl_minutes"])).isoformat(),
                "created_at": utcnow(), "reason": clean_note(reason), "verification": None,
                "policy_version": policy["version"], "dry_run": True, "threat_eradicated": False,
                "scope": {"asset_id": asset["id"], "incident_id": incident_id, "adapter": "simulation"}}
            if kind == "revoke_sessions":
                action["scope"]["entity_id"] = incident["entity_id"]
            elif kind == "block_destination":
                flows = [e for e in self.store.all("events", conn) if e["id"] in incident["event_ids"] and e["event_type"] == "network_connection" and e["external"]]
                if not flows:
                    raise HTTPException(422, "NO_EXTERNAL_DESTINATION")
                action["scope"]["destination_ip"] = flows[-1]["dst_ip"]
            action["binding_hash"] = self.action_binding(action)
            self.store.put("actions", action, conn)
            self.store.audit(user["username"], "action.proposed", action["id"], {"incident_id": incident_id, "kind": kind, "binding_hash": action["binding_hash"]}, conn)
            return action

    def transition_action(self, identifier, operation, user, reason=""):
        with self.store.transaction() as conn:
            action = self.required("actions", identifier, conn)
            policy = self.policy(conn)
            expected = {"approve": {"awaiting_approval"}, "reject": {"awaiting_approval", "approved"},
                "execute": {"approved"}, "verify": {"executed"}, "rollback": {"executed", "verified"}}
            # Repeat execution is an idempotent read: it never dispatches twice.
            if operation == "execute" and action["status"] in {"executed", "verified", "rolled_back"}:
                return action
            if action["status"] not in expected[operation]:
                raise HTTPException(409, "INVALID_ACTION_STATE")
            if operation in {"approve", "execute"}:
                if self.action_binding(action) != action["binding_hash"]:
                    raise HTTPException(409, "ACTION_BINDING_CHANGED")
                if parse_time(action["expires_at"]) <= datetime.now(timezone.utc):
                    raise HTTPException(409, "APPROVAL_EXPIRED")
                if policy["version"] != action["policy_version"]:
                    raise HTTPException(409, "POLICY_CHANGED_REPLAN")
                incident = self.required("incidents", action["incident_id"], conn)
                asset = self.required("assets", action["target"], conn)
                if asset["criticality"] == "critical" or incident["status"] == "closed":
                    raise HTTPException(403, "ACTION_POLICY_DENIED")
            if operation == "approve":
                if user["username"] == action["requested_by"]:
                    raise HTTPException(403, "SELF_APPROVAL_FORBIDDEN")
                action.update(status="approved", approved_by=user["username"], approved_at=utcnow(), approval_id=new_id("APR"))
            elif operation == "reject":
                action.update(status="rejected", rejected_by=user["username"])
            elif operation == "execute":
                if policy["kill_switch"]:
                    raise HTTPException(409, "KILL_SWITCH_ACTIVE")
                if not action["approved_by"] or action["approved_by"] == action["requested_by"]:
                    raise HTTPException(403, "APPROVAL_REQUIRED")
                action.update(status="executed", executed_at=utcnow(), provider_request_id=new_id("SIM"),
                    execution_result="simulation_acknowledged", adapter="simulation")
                # Independent state is read by verification. It is still a local simulation.
                self.store.put("simulated_adapter", {"id": action["id"], "target": action["target"],
                    "active": True, "binding_hash": action["binding_hash"]}, conn)
            elif operation == "verify":
                observed = self.required("simulated_adapter", action["id"], conn)
                success = observed["active"] and observed["target"] == action["target"] and observed["binding_hash"] == action["binding_hash"]
                action.update(status="verified" if success else "failed", verification={"method": "simulated_adapter_state_readback",
                    "effective": success, "observed_at": utcnow(), "scope": "simulation_only", "threat_eradicated": False})
                # Do not auto-close or mark a real incident contained from a simulator.
            elif operation == "rollback":
                observed = self.required("simulated_adapter", action["id"], conn)
                observed["active"] = False
                self.store.put("simulated_adapter", observed, conn)
                action.update(status="rolled_back", rolled_back_at=utcnow(), rollback_verified=True)
            self.store.put("actions", action, conn)
            self.store.audit(user["username"], f"action.{operation}", identifier, {"state": action["status"], "reason": clean_note(reason),
                "binding_hash": action["binding_hash"], "dry_run": True}, conn)
            return action
