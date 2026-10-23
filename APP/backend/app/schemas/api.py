from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.agents import AGENT_IDS

T = TypeVar("T")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{1,79}$")


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class AwsAccountIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_id: str = Field(default="000000000000", pattern=r"^\d{12}$")
    project_tag: str = Field(default="", max_length=80, pattern=r"^[A-Za-z0-9._:/=+\-@ ]*$")
    regions: list[str] = Field(default_factory=lambda: ["eu-west-2"], max_length=10)
    mode: Literal["dump", "live"] = "dump"
    dump: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    profile_ref: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9._\-]+$")


def validate_agents(v: list[str]) -> list[str]:
    bad = [a for a in v if a not in AGENT_IDS]
    if bad:
        raise ValueError(f"Unknown agents: {bad}")
    if not v:
        raise ValueError("Select at least one agent")
    return list(dict.fromkeys(v))


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=1000)
    repo_url: str = Field(max_length=500)
    branch: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._/\-]+$")
    language: str = Field(default="auto", max_length=40)
    scan_scope: list[str] = Field(default_factory=lambda: list(AGENT_IDS))
    token_secret_ref: str | None = Field(default=None, max_length=120, pattern=r"^[A-Z][A-Z0-9_]{2,119}$")
    aws: AwsAccountIn | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not NAME_RE.match(v):
            raise ValueError("Use 2–80 letters, numbers, spaces, '.', '_' or '-'")
        return re.sub(r"\s+", " ", v)

    @field_validator("scan_scope")
    @classmethod
    def _scope(cls, v: list[str]) -> list[str]:
        return validate_agents(v)


class ProjectUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    description: str | None = Field(default=None, max_length=1000)
    branch: str | None = Field(default=None, max_length=200, pattern=r"^[A-Za-z0-9._/\-]+$")
    scan_scope: list[str] | None = None

    @field_validator("scan_scope")
    @classmethod
    def _scope(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return validate_agents(v)


class RepositoryOut(ORM):
    provider: str
    url: str
    owner: str
    name: str
    branch: str | None
    last_commit: str | None
    has_token_ref: bool = False


class CloudAccountOut(ORM):
    provider: str
    account_id: str
    project_tag: str
    regions: list[str]
    services: list[str]
    mode: str
    dump_ref: str | None = None


class ProjectOut(ORM):
    id: str
    name: str
    description: str
    language: str
    scan_scope: list[str]
    created_by: str
    created_at: datetime
    repository: RepositoryOut | None = None
    cloud_account: CloudAccountOut | None = None
    stats: dict[str, Any] = Field(default_factory=dict)
    last_scan: ScanOut | None = None


class ScanOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execute_tests: bool = True
    generate_tests: bool = True
    use_llm: bool = True
    max_generated_tests: int = Field(default=8, ge=0, le=40)


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agents: list[str] | None = None
    options: ScanOptions = Field(default_factory=ScanOptions)

    @field_validator("agents")
    @classmethod
    def _agents(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return validate_agents(v)


class AgentRunOut(ORM):
    id: str
    scan_id: str
    project_id: str
    agent_id: str
    status: str
    progress: float
    attempts: int
    metrics: dict[str, Any]
    tools_used: list[str]
    findings_count: int
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None


class ScanOut(ORM):
    id: str
    project_id: str
    status: str
    agents: list[str]
    options: dict[str, Any]
    requested_by: str
    progress: float
    commit_sha: str | None
    summary: dict[str, Any]
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    agent_runs: list[AgentRunOut] = Field(default_factory=list)
    project_name: str | None = None


class ScanEventOut(ORM):
    id: int
    scan_id: str
    ts: datetime
    type: str
    agent_id: str | None
    level: str
    message: str
    progress: float | None
    data: dict[str, Any]


class ProposalOut(ORM):
    id: str
    finding_id: str
    agent_id: str
    kind: str
    title: str
    summary: str
    diff: str
    files: list[str]
    breaking: bool
    status: str
    validation: dict[str, Any]
    verification: dict[str, Any]
    branch: str | None
    base_commit: str | None
    commit_sha: str | None
    created_at: datetime
    updated_at: datetime


class ApprovalOut(ORM):
    id: str
    finding_id: str
    proposal_id: str | None
    decision: str
    actor: str
    comment: str
    created_at: datetime


class FindingOut(ORM):
    id: str
    project_id: str
    scan_id: str
    source_agent: str
    category: str
    rule_id: str
    severity: str
    title: str
    description: str
    target: str
    location: dict[str, Any]
    recommendation: str
    status: str
    confidence: str
    data_source: str
    estimated_monthly_savings: float | None
    created_at: datetime
    updated_at: datetime
    last_seen_at: datetime
    has_proposal: bool = False
    project_name: str | None = None


class TestRunOut(ORM):
    __test__ = False
    id: str
    scan_id: str
    project_id: str
    agent_id: str
    kind: str
    framework: str
    status: str
    total: int
    passed: int
    failed: int
    errors: int
    skipped: int
    coverage_before: float | None
    coverage_after: float | None
    duration_s: float | None
    details: dict[str, Any]
    report_artifact_id: str | None
    created_at: datetime


class FindingDetail(FindingOut):
    evidence: dict[str, Any]
    explanation: str
    explanation_source: str
    validation: dict[str, Any]
    proposals: list[ProposalOut] = Field(default_factory=list)
    approvals: list[ApprovalOut] = Field(default_factory=list)
    test_runs: list[TestRunOut] = Field(default_factory=list)


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    decision: Literal["accept", "dismiss", "reopen", "approve", "decline", "in_progress"]
    proposal_id: str | None = Field(default=None, max_length=40)
    comment: str = Field(default="", max_length=2000)


class RemediateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_id: str = Field(max_length=40)


class ArtifactOut(ORM):
    id: str
    scan_id: str
    agent_id: str | None
    kind: str
    name: str
    media_type: str
    size: int
    created_at: datetime


class AuditOut(ORM):
    id: int
    ts: datetime
    actor: str
    action: str
    target_type: str
    target_id: str
    outcome: str
    details: dict[str, Any]


class SettingsOut(BaseModel):
    llm: dict[str, Any]
    scan_policy: dict[str, Any]
    integrations: dict[str, Any]
    principal: dict[str, Any]


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ollama_model: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9._:\-/]+$")
    llm_enabled: bool | None = None
    default_agents: list[str] | None = None
    execute_tests: bool | None = None
    auto_generate_tests: bool | None = None

    @field_validator("default_agents")
    @classmethod
    def _agents(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return validate_agents(v)


ProjectOut.model_rebuild()
