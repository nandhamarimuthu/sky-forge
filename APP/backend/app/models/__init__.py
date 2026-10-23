"""SQLAlchemy ORM models. Secrets are never stored — only references (env var names / profile names)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("prj"))
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    language: Mapped[str] = mapped_column(String(40), default="auto")
    scan_scope: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    repository: Mapped[RepositoryConnection | None] = relationship(
        back_populates="project", uselist=False, cascade="all, delete-orphan")
    cloud_account: Mapped[CloudAccountReference | None] = relationship(
        back_populates="project", uselist=False, cascade="all, delete-orphan")


class RepositoryConnection(Base):
    __tablename__ = "repository_connections"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("repo"))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), unique=True)
    provider: Mapped[str] = mapped_column(String(20))  # github | gitlab | bitbucket | local-fixture
    url: Mapped[str] = mapped_column(String(500))
    owner: Mapped[str] = mapped_column(String(100), default="")
    name: Mapped[str] = mapped_column(String(200), default="")
    branch: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Name of an environment variable holding a token for private repos; the token itself is never stored.
    token_secret_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    project: Mapped[Project] = relationship(back_populates="repository")


class CloudAccountReference(Base):
    __tablename__ = "cloud_account_references"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("acct"))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), unique=True)
    provider: Mapped[str] = mapped_column(String(20), default="aws")
    account_id: Mapped[str] = mapped_column(String(20))
    project_tag: Mapped[str] = mapped_column(String(80), default="")
    profile_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)
    regions: Mapped[list[str]] = mapped_column(JSON, default=list)
    services: Mapped[list[str]] = mapped_column(JSON, default=list)
    mode: Mapped[str] = mapped_column(String(10), default="dump")  # dump | live
    # "fixture:<name>" (bundled export) or "upload" (zip uploaded for this project).
    dump_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    project: Mapped[Project] = relationship(back_populates="cloud_account")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("scan"))
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    # queued | running | completed | partial | failed | cancelled
    agents: Mapped[list[str]] = mapped_column(JSON, default=list)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    requested_by: Mapped[str] = mapped_column(String(80))
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanEvent(Base):
    __tablename__ = "scan_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    type: Mapped[str] = mapped_column(String(30))  # scan.status | agent.status | agent.log | progress | finding
    agent_id: Mapped[str | None] = mapped_column(String(30), nullable=True)
    level: Mapped[str] = mapped_column(String(10), default="info")
    message: Mapped[str] = mapped_column(Text, default="")
    progress: Mapped[float | None] = mapped_column(Float, nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class AgentRun(Base):
    __tablename__ = "agent_runs"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("run"))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    # queued | running | completed | failed | cancelled | skipped | timed_out
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tools_used: Mapped[list[str]] = mapped_column(JSON, default=list)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("project_id", "fingerprint", name="uq_finding_fingerprint"),)
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    first_scan_id: Mapped[str] = mapped_column(String(40))
    fingerprint: Mapped[str] = mapped_column(String(64))
    source_agent: Mapped[str] = mapped_column(String(30), index=True)
    category: Mapped[str] = mapped_column(String(30), index=True)
    rule_id: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    target: Mapped[str] = mapped_column(String(500), default="")
    location: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    # open | accepted | in_progress | fixed | verified | dismissed
    confidence: Mapped[str] = mapped_column(String(10), default="medium")
    data_source: Mapped[str] = mapped_column(String(12), default="measured")  # measured | estimated | simulated
    estimated_monthly_savings: Mapped[float | None] = mapped_column(Float, nullable=True)
    explanation: Mapped[str] = mapped_column(Text, default="")
    explanation_source: Mapped[str] = mapped_column(String(20), default="template")  # template | llm
    validation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    proposals: Mapped[list[RemediationProposal]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="RemediationProposal.created_at")


class RemediationProposal(Base):
    __tablename__ = "remediation_proposals"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("fix"))
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    agent_id: Mapped[str] = mapped_column(String(30))
    kind: Mapped[str] = mapped_column(String(30))
    title: Mapped[str] = mapped_column(String(300))
    summary: Mapped[str] = mapped_column(Text, default="")
    diff: Mapped[str] = mapped_column(Text, default="")
    files: Mapped[list[str]] = mapped_column(JSON, default=list)
    breaking: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(24), default="proposed")
    # proposed | validated | rejected_by_policy | approved | declined | applied | verified | verification_failed
    validation: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    verification: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    branch: Mapped[str | None] = mapped_column(String(200), nullable=True)
    base_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="proposals")


class TestRun(Base):
    __tablename__ = "test_runs"
    __test__ = False  # stop pytest from collecting this ORM class
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("tr"))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[str] = mapped_column(String(30))
    kind: Mapped[str] = mapped_column(String(20))  # unit | functional | verification
    framework: Mapped[str] = mapped_column(String(40), default="pytest")
    status: Mapped[str] = mapped_column(String(20))  # passed | failed | error | skipped | not_executed
    total: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    coverage_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    coverage_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    duration_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report_artifact_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("art"))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(30), nullable=True)
    kind: Mapped[str] = mapped_column(String(30))  # patch | test_file | report | log | sbom
    name: Mapped[str] = mapped_column(String(200))
    rel_path: Mapped[str] = mapped_column(String(500))
    media_type: Mapped[str] = mapped_column(String(80), default="text/plain")
    size: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: new_id("apr"))
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    proposal_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    decision: Mapped[str] = mapped_column(String(20))  # approve | decline | accept | dismiss | reopen
    actor: Mapped[str] = mapped_column(String(80))
    comment: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80), index=True)
    target_type: Mapped[str] = mapped_column(String(40), default="")
    target_id: Mapped[str] = mapped_column(String(80), default="")
    outcome: Mapped[str] = mapped_column(String(16), default="allowed")  # allowed | denied | error | info
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)
    updated_by: Mapped[str] = mapped_column(String(80), default="system")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
