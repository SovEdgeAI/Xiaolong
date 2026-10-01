"""SQLAlchemy ORM models for the RA3 system (4 tables)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    TIMESTAMP,
    Float,
    ForeignKey,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class Action(Base):
    """Static catalog of available response actions."""

    __tablename__ = "actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    applicable_threats: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list
    )
    parameters_schema: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    severity_threshold: Mapped[str] = mapped_column(
        String(20), nullable=False, default="low"
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )


class Incident(Base):
    """A reported threat event from an upstream (RA1) detector."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    client_id: Mapped[str] = mapped_column(String(100), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    # NB: `metadata` is reserved on the Declarative base, so the Python
    # attribute is `meta` while the DB column stays `metadata`.
    meta: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending"
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    responses: Mapped[list["Response"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class Response(Base):
    """The LLM decision result for a given incident."""

    __tablename__ = "responses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    selected_actions: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )
    # Actual execution outcome per action, produced by the MCP executor.
    execution_results: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list
    )
    llm_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_llm_response: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )

    incident: Mapped["Incident"] = relationship(back_populates="responses")


class TrainingJob(Base):
    """A fine-tuning job for the local decision model (not an incident response)."""

    __tablename__ = "training_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # queued -> running -> succeeded | failed | lost
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued")
    trigger: Mapped[str] = mapped_column(String(50), nullable=False)   # manual | auto:<rule>
    mode: Mapped[str] = mapped_column(String(20), nullable=False)      # dry_run | train
    spec: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)  # trainer status.json
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now()
    )
