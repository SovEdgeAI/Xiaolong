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

class ReportRequest(BaseModel):
    client_id: str = Field(..., examples=["bs_node_01"])
    attack_type: AttackType
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SelectedAction(BaseModel):
    """One action chosen by the LLM, with its arguments and rationale."""

    name: str
    order: int
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


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
