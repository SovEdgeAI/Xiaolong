"""FastAPI routes: /report, /incidents, /actions, /health."""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import llm
import mcp_client
from database import check_connection, get_session
from models import Action, Incident, Response
from schemas import (
    ActionOut,
    ExecutionOutcome,
    HealthResponse,
    IncidentDetail,
    IncidentList,
    IncidentSummary,
    ReportRequest,
    ReportResponse,
    SelectedAction,
)

logger = logging.getLogger("ra3.router")

router = APIRouter()


# ---------------------------------------------------------------------------
# POST /report — ingest a threat, run the LLM decision, persist, return it
# ---------------------------------------------------------------------------
@router.post("/report", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def report_threat(
    payload: ReportRequest,
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    # Normal traffic needs no response; short-circuit before touching the LLM.
    if payload.attack_type.value == "Normal":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="attack_type 'Normal' requires no response action.",
        )

    # 1. Persist the incident first so we have an ID to hand to the LLM.
    incident = Incident(
        client_id=payload.client_id,
        attack_type=payload.attack_type.value,
        severity=payload.severity.value,
        confidence=payload.confidence,
        meta=payload.metadata,
        status="pending",
    )
    session.add(incident)
    await session.flush()  # assigns incident.id without committing yet

    # 2. Ask Claude to choose the response actions.
    try:
        decision = llm.decide_actions(
            incident_id=str(incident.id),
            client_id=incident.client_id,
            attack_type=incident.attack_type,
            severity=incident.severity,
            confidence=incident.confidence,
            metadata=incident.meta,
        )
    except llm.LLMError as exc:
        # Roll back the pending incident insert; report a clean 502 upstream.
        await session.rollback()
        logger.error("LLM decision failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM decision failed: {exc}",
        ) from exc

    # 3. Actually execute the selected actions via the MCP server (each action
    #    runs in an ephemeral executor container). Best-effort: failures are
    #    recorded per action rather than aborting the request.
    execution_results = await mcp_client.execute_actions(decision["selected_actions"])

    # 4. Store the decision + execution outcome; mark the incident status.
    all_ok = bool(execution_results) and all(
        r.get("execution", {}).get("status") == "success" for r in execution_results
    )
    response = Response(
        incident_id=incident.id,
        selected_actions=decision["selected_actions"],
        execution_results=execution_results,
        llm_reasoning=decision["llm_reasoning"],
        raw_llm_response=decision["raw_llm_response"],
    )
    session.add(response)
    incident.status = "resolved" if all_ok else "responded"

    try:
        await session.commit()
    except Exception as exc:  # noqa: BLE001
        await session.rollback()
        logger.exception("Failed to persist decision")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist decision.",
        ) from exc

    return ReportResponse(
        incident_id=incident.id,
        attack_type=incident.attack_type,
        severity=incident.severity,
        selected_actions=[SelectedAction(**a) for a in decision["selected_actions"]],
        execution_results=[ExecutionOutcome(**r) for r in execution_results],
        llm_reasoning=decision["llm_reasoning"],
    )


# ---------------------------------------------------------------------------
# GET /incidents — filtered, paginated history
# ---------------------------------------------------------------------------
@router.get("/incidents", response_model=IncidentList)
async def list_incidents(
    attack_type: str | None = Query(None),
    severity: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> IncidentList:
    filters = []
    if attack_type:
        filters.append(Incident.attack_type == attack_type)
    if severity:
        filters.append(Incident.severity == severity)
    if status_filter:
        filters.append(Incident.status == status_filter)

    count_stmt = select(func.count()).select_from(Incident)
    list_stmt = select(Incident).order_by(Incident.created_at.desc())
    for f in filters:
        count_stmt = count_stmt.where(f)
        list_stmt = list_stmt.where(f)

    total = (await session.execute(count_stmt)).scalar_one()
    rows = (
        (await session.execute(list_stmt.limit(limit).offset(offset)))
        .scalars()
        .all()
    )

    return IncidentList(
        total=total,
        limit=limit,
        offset=offset,
        items=[IncidentSummary.model_validate(r) for r in rows],
    )


# ---------------------------------------------------------------------------
# GET /incidents/{incident_id} — full detail incl. LLM decision
# ---------------------------------------------------------------------------
@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> IncidentDetail:
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found.",
        )
    return IncidentDetail.model_validate(incident)


# ---------------------------------------------------------------------------
# GET /actions — the response action catalog
# ---------------------------------------------------------------------------
@router.get("/actions", response_model=list[ActionOut])
async def list_actions(
    session: AsyncSession = Depends(get_session),
) -> list[ActionOut]:
    rows = (
        (await session.execute(select(Action).order_by(Action.name)))
        .scalars()
        .all()
    )
    return [ActionOut.model_validate(r) for r in rows]


# ---------------------------------------------------------------------------
# GET /health — service + DB connectivity probe
# ---------------------------------------------------------------------------
@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    db_ok = await check_connection()
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        database="connected" if db_ok else "disconnected",
    )
