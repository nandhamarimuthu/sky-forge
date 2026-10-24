"""Typed contracts for agent outputs. Agent output is untrusted: it is validated here before persistence."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.security import redact

AgentId = Literal["vulnerability", "unit_test", "functional_test", "aws_optimizer", "code_health", "guardrails"]
AGENT_IDS: tuple[str, ...] = ("vulnerability", "unit_test", "functional_test", "aws_optimizer", "code_health",
                              "guardrails")
Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
Category = Literal["vulnerability", "coverage", "functional", "cost", "anomaly", "code_health", "secret",
                   "security_policy", "iac"]
ProposalKind = Literal["dependency_upgrade", "test_addition", "functional_test", "refactor", "config_fix",
                       "iac_change", "advisory"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ProposalDraft(_Strict):
    # Diffs are whitespace-significant (trailing blank context lines, final newline) — never strip them.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    kind: ProposalKind
    title: str = Field(max_length=300)
    summary: str = Field(default="", max_length=4000)
    diff: str = Field(default="", max_length=400_000)
    files: list[str] = Field(default_factory=list, max_length=50)
    breaking: bool = False
    # Deterministic recipe to rebuild the patch at apply time when the stored diff must stay redacted.
    codemod: dict[str, Any] | None = None


class FindingDraft(_Strict):
    rule_id: str = Field(max_length=120)
    category: Category
    severity: Severity
    title: str = Field(max_length=300)
    description: str = Field(default="", max_length=8000)
    target: str = Field(default="", max_length=500)
    location: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str = Field(default="", max_length=4000)
    confidence: Literal["high", "medium", "low"] = "medium"
    data_source: Literal["measured", "estimated", "simulated"] = "measured"
    estimated_monthly_savings: float | None = Field(default=None, ge=0)
    fingerprint_key: str = Field(max_length=500)
    proposal: ProposalDraft | None = None

    @field_validator("title", "description", "recommendation")
    @classmethod
    def _redact(cls, v: str) -> str:
        return redact(v)


class TestRunDraft(_Strict):
    __test__ = False
    kind: Literal["unit", "functional", "verification"]
    framework: str = "pytest"
    status: Literal["passed", "failed", "error", "skipped", "not_executed"]
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    coverage_before: float | None = None
    coverage_after: float | None = None
    duration_s: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    report_name: str | None = None
    report_content: str | None = None


class ArtifactDraft(_Strict):
    kind: Literal["patch", "test_file", "report", "log", "inventory"]
    name: str = Field(max_length=200, pattern=r"^[A-Za-z0-9._\-]+$")
    content: str = Field(max_length=2_000_000)
    media_type: str = "text/plain"


class AgentResult(_Strict):
    agent_id: AgentId
    status: Literal["completed", "partial", "failed", "skipped"] = "completed"
    findings: list[FindingDraft] = Field(default_factory=list)
    test_runs: list[TestRunDraft] = Field(default_factory=list)
    artifacts: list[ArtifactDraft] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    tools_used: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
