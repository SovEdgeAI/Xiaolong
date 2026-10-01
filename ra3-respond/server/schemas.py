"""Pydantic request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# --- Enumerations shared across the API ------------------------------------

class AttackType(str, Enum):
    """The 9 threat classes from the 5G-NIDD dataset (Normal excluded from response)."""

    ICMP_FLOOD = "ICMP_Flood"
    UDP_FLOOD = "UDP_Flood"
    SYN_FLOOD = "SYN_Flood"
    HTTP_FLOOD = "HTTP_Flood"
    SLOWRATE_DOS = "Slowrate_DoS"
    SYN_SCAN = "SYN_Scan"
    TCP_CONNECT_SCAN = "TCP_Connect_Scan"
    UDP_SCAN = "UDP_Scan"
    NORMAL = "Normal"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- POST /report ----------------------------------------------------------

KNOWN_ATTACK_TYPES = {a.value for a in AttackType}


class ReportRequest(BaseModel):
    client_id: str = Field(..., examples=["bs_node_01"])
    # Accept ANY attack label, not just the 8 known 5G-NIDD classes: a detector
    # may report a new/unknown attack, and RA3 should still respond (the LLM
    # decides from the catalog, with a behaviour-based fallback) rather than
    # rejecting it. Known types still get their tuned policy; "Normal" is
    # rejected in the route.
    attack_type: str = Field(..., min_length=1, examples=["SYN_Flood", "DNS_Amplification"])
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SelectedAction(BaseModel):
    """One action chosen by the LLM, with its arguments and rationale."""

    name: str
    order: int
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    # Decision confidence in [0, 1] (local decision model only; 1.0 for mandatory rules).
    confidence: float | None = None


class ExecutionOutcome(BaseModel):
    """The actual execution result of one action (from the MCP executor)."""

    name: str
    order: int | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    execution: dict[str, Any] = Field(default_factory=dict)


class ReportResponse(BaseModel):
    incident_id: uuid.UUID
    attack_type: str
    severity: str
    selected_actions: list[SelectedAction]
    execution_results: list[ExecutionOutcome] = Field(default_factory=list)
    llm_reasoning: str | None = None
    # Structured per-action rationale + confidence (LLM_MODEL=anyjev), else null.
    explanation: dict[str, Any] | None = None


# --- GET /incidents --------------------------------------------------------

class IncidentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    client_id: str
    attack_type: str
    severity: str
    confidence: float
    status: str
    created_at: datetime


class ResponseDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    selected_actions: list[dict[str, Any]]
    execution_results: list[dict[str, Any]] = Field(default_factory=list)
    llm_reasoning: str | None
    created_at: datetime


class IncidentDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    client_id: str
    attack_type: str
    severity: str
    confidence: float
    metadata: dict[str, Any] = Field(validation_alias="meta")
    status: str
    created_at: datetime
    updated_at: datetime
    responses: list[ResponseDetail] = Field(default_factory=list)


class IncidentList(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IncidentSummary]


# --- GET /actions ----------------------------------------------------------

class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    display_name: str
    description: str
    applicable_threats: list[str]
    parameters_schema: dict[str, Any]
    severity_threshold: str


# --- GET /health -----------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    database: str


# --- /training/jobs ---------------------------------------------------------

class TrainingMode(str, Enum):
    DRY_RUN = "dry_run"   # validate data + environment, write the plan, train nothing
    TRAIN = "train"       # real fine-tune (needs a GPU trainer image)


class TrainingJobCreate(BaseModel):
    mode: TrainingMode = TrainingMode.DRY_RUN
    base_model: str | None = Field(None, description="default: FINETUNE_BASE_MODEL / JEV_MODEL")
    dataset: str | None = Field(None, description="file name under ./artifacts (default: FINETUNE_DATASET)")
    method: str = "lora"
    hyperparams: dict[str, Any] = Field(default_factory=dict)
    simulate_seconds: float = Field(0, ge=0, le=600, description="dry_run only: keep the job running this long")


class TrainingJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: str
    trigger: str
    mode: str
    spec: dict[str, Any]
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime
