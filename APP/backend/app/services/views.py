"""Read-model helpers shared by API routes."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.adapters.aws.base import AwsAdapter
from app.adapters.aws.factory import build_aws_adapter
from app.adapters.repository.git_repo import RepoWorkspace
from app.adapters.scanners.terraform import parse_terraform
from app.agents.aws_optimizer_agent import iac_hints
from app.models import AgentRun, Finding, Project, Scan
from app.orchestration.orchestrator import workspace_dir
from app.schemas.api import AgentRunOut, CloudAccountOut, ProjectOut, RepositoryOut, ScanOut
from app.services.container import Container

OPEN_STATUSES = ("open", "accepted", "in_progress")


def scan_out(db: Session, scan: Scan, with_runs: bool = True, project_name: str | None = None) -> ScanOut:
    out = ScanOut.model_validate(scan)
    if with_runs:
        runs = db.execute(select(AgentRun).where(AgentRun.scan_id == scan.id).order_by(AgentRun.agent_id)).scalars()
        out.agent_runs = [AgentRunOut.model_validate(r) for r in runs]
    out.project_name = project_name
    return out


def project_out(db: Session, p: Project) -> ProjectOut:
    out = ProjectOut.model_validate({
        "id": p.id, "name": p.name, "description": p.description, "language": p.language,
        "scan_scope": p.scan_scope, "created_by": p.created_by,
        "created_at": p.created_at,
    })
    if p.repository:
        out.repository = RepositoryOut.model_validate(p.repository)
        out.repository.has_token_ref = bool(p.repository.token_secret_ref)
    if p.cloud_account:
        out.cloud_account = CloudAccountOut.model_validate(p.cloud_account)
    sev: dict[str, int] = {k: v for k, v in db.execute(select(Finding.severity, func.count()).where(
        Finding.project_id == p.id, Finding.status.in_(OPEN_STATUSES)).group_by(Finding.severity)).all()}
    savings = db.execute(select(func.coalesce(func.sum(Finding.estimated_monthly_savings), 0.0)).where(
        Finding.project_id == p.id, Finding.status.in_(OPEN_STATUSES))).scalar_one()
    assert savings is not None  # coalesce(..., 0.0) never yields NULL
    last = db.execute(select(Scan).where(Scan.project_id == p.id).order_by(Scan.created_at.desc()).limit(1)
                      ).scalar_one_or_none()
    last_done = db.execute(select(Scan).where(Scan.project_id == p.id, Scan.status.in_(["completed", "partial"]))
                           .order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
    summary = last_done.summary if last_done else {}
    out.stats = {"open_by_severity": sev, "open_total": sum(sev.values()), "estimated_monthly_savings": round(savings, 2),
                 "coverage": summary.get("coverage_after") or summary.get("coverage"),
                 "coverage_before": summary.get("coverage"), "health_score": summary.get("health_score"),
                 "vulnerabilities": db.execute(select(func.count()).where(
                     Finding.project_id == p.id, Finding.category.in_(["vulnerability", "secret", "security_policy",
                                                                       "iac"]),
                     Finding.status.in_(OPEN_STATUSES))).scalar_one()}
    if last:
        out.last_scan = scan_out(db, last, with_runs=True)
    return out


def latest_workspace(c: Container, db: Session, project_id: str) -> RepoWorkspace | None:
    scans = db.execute(select(Scan.id).where(Scan.project_id == project_id).order_by(Scan.created_at.desc())
                       .limit(5)).scalars()
    for sid in scans:
        root = workspace_dir(c.settings, project_id, sid) / "repo"
        if root.exists():
            return RepoWorkspace(root)
    return None


def aws_adapter_for(c: Container, db: Session, project: Project) -> AwsAdapter:
    ws = latest_workspace(c, db, project.id)
    hints = iac_hints(parse_terraform(ws)) if ws else []
    return build_aws_adapter(c.settings, project.cloud_account, hints)


def latest_agent_metrics(db: Session, project_id: str, agent_id: str) -> tuple[dict[str, Any], str | None]:
    run = db.execute(select(AgentRun).where(AgentRun.project_id == project_id, AgentRun.agent_id == agent_id,
                                            AgentRun.status == "completed").order_by(AgentRun.finished_at.desc())
                     .limit(1)).scalar_one_or_none()
    return (run.metrics or {}, run.scan_id) if run else ({}, None)
