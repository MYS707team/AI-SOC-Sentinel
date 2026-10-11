from datetime import datetime, timezone
import ipaddress
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class TelemetryEvent(StrictModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,100}$")
    source: Literal["identity", "endpoint", "network", "core_banking"]
    event_type: Literal["login_failed", "login_success", "process_start", "network_connection", "privilege_change", "payment_access"]
    event_time: str
    asset_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,80}$")
    entity_id: str = Field(min_length=1, max_length=120)
    src_ip: str = "192.0.2.1"
    dst_ip: str = "192.0.2.2"
    bytes_out: int = Field(default=0, ge=0, le=10**13)
    privileged: bool = False
    unusual_process: bool = False
    external: bool = False

    @field_validator("event_time")
    @classmethod
    def timestamp(cls, value):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("UTC offset is required")
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except (TypeError, ValueError) as exc:
            raise ValueError("ISO 8601 timestamp with UTC offset required") from exc

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ipaddress.ip_address(value))


class IngestBatch(StrictModel):
    events: list[TelemetryEvent] = Field(min_length=1, max_length=200)


class Login(StrictModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class DemoLogin(StrictModel):
    role: Literal["analyst", "approver", "auditor", "admin", "ml_engineer"] = "analyst"


class Reason(StrictModel):
    reason: str = Field(min_length=8, max_length=600)


class LabelRequest(Reason):
    label: Literal["malicious", "benign", "uncertain"]


class ReviewRequest(Reason):
    decision: Literal["approve", "reject"]


class IncidentStatus(StrictModel):
    status: Literal["open", "investigating", "contained", "closed"]
    owner: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9_.@-]*$")


class ActionRequest(Reason):
    kind: Literal["isolate_endpoint", "revoke_sessions", "block_destination"]


class ReplayRequest(StrictModel):
    scenario: Literal["credential_compromise", "exfiltration", "benign", "mixed"] = "mixed"


class PolicyRequest(StrictModel):
    kill_switch: bool


class TrainRequest(StrictModel):
    dataset_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviewed: Literal[True]


class LabRequest(StrictModel):
    path: Literal["/search", "/echo", "/file", "/login"] = "/search"
    payload: str = Field(default="books", max_length=3500)
    method: Literal["GET", "POST"] = "GET"


class LabFeedback(LabelRequest):
    disposition: Literal["block", "release", "escalate", "monitor"] = "monitor"


class LabPolicy(StrictModel):
    auto_block: bool

