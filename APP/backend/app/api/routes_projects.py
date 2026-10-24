from __future__ import annotations

import re
import statistics

from fastapi import APIRouter, Depends, File, Query, Request, Response, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.adapters.repository.git_repo import RepositoryError, parse_repo_url
from app.agents import AGENTS
from app.api.deps import accessible_project_ids, client_ip, container, get_principal, load_project, require
from app.core.errors import ApiError
from app.core.ratelimit import rate_limiter
from app.core.security import Principal
from app.db.session import get_db
from app.models import (
    AgentRun,
    CloudAccountReference,
    Finding,
    Project,
    RemediationProposal,
    RepositoryConnection,
    Scan,
    Setting,
)
from app.schemas.api import Page, ProjectCreate, ProjectOut, ProjectUpdate, ScanCreate, ScanOut
from app.services.audit import audit
from app.services.container import Container
from app.services.views import OPEN_STATUSES, aws_adapter_for, latest_agent_metrics, project_out, scan_out

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=Page[ProjectOut])
def list_projects(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=100),
                  q: str | None = Query(None, max_length=80), db: Session = Depends(get_db),
                  principal: Principal = Depends(get_principal)) -> Page[ProjectOut]:
    ids = accessible_project_ids(db, principal)
    stmt = select(Project).where(Project.id.in_(ids))
    if q:
        stmt = stmt.where(Project.name.ilike(f"%{q}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(Project.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
                      ).scalars().all()
    return Page(items=[project_out(db, p) for p in rows], total=total, page=page, page_size=page_size)


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(body: ProjectCreate, request: Request, db: Session = Depends(get_db),
                   principal: Principal = Depends(require("project:create")),
                   c: Container = Depends(container)) -> ProjectOut:
    try:
        ref = parse_repo_url(body.repo_url, c.settings.git_hosts, c.settings.fixtures_dir)
    except RepositoryError as exc:
        raise ApiError(422, "invalid_repository", str(exc)) from exc
    if db.execute(select(Project).where(func.lower(Project.name) == body.name.lower())).scalar_one_or_none():
        raise ApiError(409, "duplicate_name", f"A project named '{body.name}' already exists")
    if body.aws:
        bad = [r for r in body.aws.regions if r not in c.settings.region_allowlist]
        if bad:
            raise ApiError(422, "region_not_allowed", f"Regions not in allowlist: {bad}")
    project = Project(name=body.name, description=body.description, language=body.language,
                      scan_scope=body.scan_scope, created_by=principal.name)
    project.repository = RepositoryConnection(provider=ref.provider, url=ref.url, owner=ref.owner, name=ref.name,
                                              branch=body.branch, token_secret_ref=body.token_secret_ref)
    aws = body.aws
    account_id = aws.account_id if aws else "000000000000"
    regions = aws.regions if aws else [c.settings.aws_region]
    tag = aws.project_tag if aws and aws.project_tag else re.sub(r"[^a-z0-9-]+", "-", body.name.lower())
    project.cloud_account = CloudAccountReference(
        account_id=account_id, project_tag=tag, regions=regions, services=c.settings.service_allowlist,
        mode="dump", dump_ref="terraform")
    db.add(project)
    db.flush()
    audit(db, principal.name, "project.create", "project", project.id, "allowed",
          {"repo": ref.url, "agents": body.scan_scope}, client_ip(request))
    db.refresh(project)
    return project_out(db, project)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, request: Request, db: Session = Depends(get_db),
                principal: Principal = Depends(get_principal)) -> ProjectOut:
    return project_out(db, load_project(db, principal, project_id, request))


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(project_id: str, body: ProjectUpdate, request: Request, db: Session = Depends(get_db),
                   principal: Principal = Depends(require("project:create"))) -> ProjectOut:
    p = load_project(db, principal, project_id, request)
    if body.description is not None:
        p.description = body.description
    if body.scan_scope is not None:
        p.scan_scope = body.scan_scope
    if body.branch is not None and p.repository:
        p.repository.branch = body.branch or None
    audit(db, principal.name, "project.update", "project", p.id, "allowed", body.model_dump(exclude_none=True),
          client_ip(request))
    return project_out(db, p)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
def delete_project(project_id: str, request: Request, db: Session = Depends(get_db),
                   principal: Principal = Depends(require("project:delete"))) -> Response:
    p = load_project(db, principal, project_id, request)
    if db.execute(select(Scan).where(Scan.project_id == p.id, Scan.status.in_(["queued", "running"]))).first():
        raise ApiError(409, "scan_running", "Cancel running scans before deleting the project")
    db.delete(p)
    audit(db, principal.name, "project.delete", "project", project_id, "allowed", {"name": p.name},
          client_ip(request))
    return Response(status_code=204)


@router.get("/{project_id}/scans", response_model=Page[ScanOut])
def project_scans(project_id: str, request: Request, page: int = Query(1, ge=1),
                  page_size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db),
                  principal: Principal = Depends(get_principal)) -> Page[ScanOut]:
    p = load_project(db, principal, project_id, request)
    stmt = select(Scan).where(Scan.project_id == p.id)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).scalars()
    return Page(items=[scan_out(db, s, project_name=p.name) for s in rows], total=total, page=page,
                page_size=page_size)


@router.post("/{project_id}/scans", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def start_scan(project_id: str, request: Request, body: ScanCreate | None = None, db: Session = Depends(get_db),
               principal: Principal = Depends(require("scan:run")), c: Container = Depends(container)) -> ScanOut:
    body = body or ScanCreate()
    p = load_project(db, principal, project_id, request)
    ok, retry = rate_limiter.allow(f"scan:{principal.name}", c.settings.scan_rate_limit_per_minute)
    if not ok:
        raise ApiError(429, "rate_limited", f"Scan rate limit reached; retry in {retry}s")
    if db.execute(select(Scan).where(Scan.project_id == p.id, Scan.status.in_(["queued", "running"]))).first():
        raise ApiError(409, "scan_in_progress", "A scan is already queued or running for this project")
    defaults = db.get(Setting, "scan_policy")
    policy = defaults.value if defaults else {}
    options = body.options.model_dump()
    if "execute_tests" in policy and not policy["execute_tests"]:
        options["execute_tests"] = False
    agents = body.agents or p.scan_scope or list(AGENTS)
    scan = Scan(project_id=p.id, agents=agents, options=options, requested_by=principal.name)
    db.add(scan)
    db.flush()
    audit(db, principal.name, "scan.start", "scan", scan.id, "allowed", {"project": p.id, "agents": agents},
          client_ip(request))
    c.worker.submit(scan.id)
    return scan_out(db, scan, project_name=p.name)


# ---------------------------------------------------------------- AWS


@router.get("/{project_id}/aws/resources")
def aws_resources(project_id: str, request: Request, db: Session = Depends(get_db),
                  principal: Principal = Depends(get_principal), c: Container = Depends(container)) -> dict:
    p = load_project(db, principal, project_id, request)
    adapter = aws_adapter_for(c, db, p)
    findings = db.execute(select(Finding).where(Finding.project_id == p.id, Finding.category == "cost",
                                                Finding.status.in_(OPEN_STATUSES))).scalars().all()
    by_resource = {(f.location or {}).get("resource_id"): f for f in findings
                   if (f.evidence or {}).get("scope", {}).get("terraform_fingerprint")
                   == adapter.report.meta["terraform_fingerprint"]}
    items = []
    for r in adapter.inventory():
        metrics = {m.metric: {"avg": round(statistics.fmean(v for _, v in m.points), 2) if m.points else None,
                              "max": max((v for _, v in m.points), default=None), "unit": m.unit,
                              "points": m.points} for m in adapter.metrics(r)}
        f = by_resource.get(r.id)
        items.append({"id": r.id, "service": r.service, "region": r.region, "type": r.type, "state": r.state,
                      "name": r.name, "tags": r.tags, "config": r.config, "monthly_cost": r.monthly_cost,
                      "iac_address": r.iac_address, "metrics": metrics,
                      "recommendation": {"finding_id": f.id, "title": f.title, "savings": f.estimated_monthly_savings,
                                         "confidence": f.confidence} if f else None})
    return {"mode": adapter.report.mode, "simulated": adapter.report.simulated, "source": adapter.report.meta,
            "errors": adapter.report.errors[:10], "items": items,
            "missing_evidence": adapter.report.missing_evidence[:20],
            "account": {"account_id": p.cloud_account.account_id, "regions": p.cloud_account.regions,
                        "project_tag": p.cloud_account.project_tag} if p.cloud_account else None}


@router.get("/{project_id}/aws/cost")
def aws_cost(project_id: str, request: Request, days: int = Query(90, ge=7, le=180), db: Session = Depends(get_db),
             principal: Principal = Depends(get_principal), c: Container = Depends(container)) -> dict:
    p = load_project(db, principal, project_id, request)
    adapter = aws_adapter_for(c, db, p)
    cost = adapter.cost(days)
    findings = db.execute(select(Finding).where(Finding.project_id == p.id,
                                                Finding.category.in_(["cost", "anomaly"]))).scalars().all()
    open_f = [f for f in findings if f.status in OPEN_STATUSES
              and (f.evidence or {}).get("scope", {}).get("terraform_fingerprint")
              == adapter.report.meta["terraform_fingerprint"]]
    approved = db.execute(select(RemediationProposal).where(
        RemediationProposal.project_id == p.id, RemediationProposal.kind == "iac_change",
        RemediationProposal.status.in_(["approved", "applying", "applied", "verified"]))).scalars().all()
    by_rule: dict[str, float] = {}
    for f in open_f:
        key = f.rule_id.replace("aws:", "")
        by_rule[key] = round(by_rule.get(key, 0) + (f.estimated_monthly_savings or 0), 2)
    daily_total: dict[str, float] = {}
    if cost:
        for pts in cost.by_service.values():
            for d, v in pts:
                daily_total[d] = round(daily_total.get(d, 0) + v, 2)
    return {
        "mode": adapter.report.mode, "simulated": adapter.report.simulated, "source": adapter.report.meta,
        "errors": adapter.report.errors[:10],
        "measured_spend": bool(cost and cost.measured), "currency": cost.currency if cost else "USD",
        "by_service": cost.by_service if cost else {}, "daily_total": sorted(daily_total.items()),
        "last_30_days": round(sum(v for _, v in sorted(daily_total.items())[-30:]), 2),
        "estimated_monthly_savings": round(sum(f.estimated_monthly_savings or 0 for f in open_f), 2),
        "savings_by_rule": by_rule,
        "recommendations": [{"id": f.id, "title": f.title, "severity": f.severity, "rule": f.rule_id,
                             "savings": f.estimated_monthly_savings, "confidence": f.confidence,
                             "savings_type": (f.evidence or {}).get("savings_type"), "status": f.status,
                             "category": f.category, "has_iac_patch": bool(f.proposals)} for f in open_f],
        "approved_changes": [{"proposal_id": pr.id, "finding_id": pr.finding_id, "title": pr.title,
                              "status": pr.status, "branch": pr.branch} for pr in approved],
        "missing_evidence": adapter.report.missing_evidence[:20],
    }


@router.get("/{project_id}/quality")
def quality(project_id: str, request: Request, db: Session = Depends(get_db),
            principal: Principal = Depends(get_principal)) -> dict:
    p = load_project(db, principal, project_id, request)
    metrics, scan_id = latest_agent_metrics(db, p.id, "code_health")
    history = [{"scan_id": r.scan_id, "date": r.finished_at, "health_score": (r.metrics or {}).get("health_score"),
                "lint_issues": (r.metrics or {}).get("lint_issues"),
                "avg_complexity": (r.metrics or {}).get("avg_complexity")}
               for r in db.execute(select(AgentRun).where(AgentRun.project_id == p.id,
                                                          AgentRun.agent_id == "code_health",
                                                          AgentRun.status == "completed")
                                   .order_by(AgentRun.finished_at)).scalars()]
    findings = db.execute(select(Finding).where(Finding.project_id == p.id, Finding.category == "code_health")
                          .order_by(Finding.severity)).scalars().all()
    refactors = db.execute(select(RemediationProposal).where(RemediationProposal.project_id == p.id,
                                                             RemediationProposal.kind == "refactor")).scalars().all()
    return {"metrics": metrics, "scan_id": scan_id, "history": history,
            "findings": [{"id": f.id, "title": f.title, "severity": f.severity, "rule": f.rule_id,
                          "target": f.target, "line": (f.location or {}).get("line"), "status": f.status,
                          "evidence": f.evidence} for f in findings[:200]],
            "refactors": [{"id": r.id, "finding_id": r.finding_id, "title": r.title, "status": r.status,
                           "summary": r.summary, "verification": r.verification} for r in refactors]}


# ---------------------------------------------------------------- AWS data source

class AwsSourceUpdate(BaseModel):
    dump: str = Field(max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    project_tag: str | None = Field(default=None, max_length=80, pattern=r"^[A-Za-z0-9._:/=+\-@ ]*$")


@router.put("/{project_id}/aws/source")
def set_aws_source(project_id: str, body: AwsSourceUpdate, request: Request, db: Session = Depends(get_db),
                   principal: Principal = Depends(require("project:create")),
                   c: Container = Depends(container)) -> dict:
    load_project(db, principal, project_id, request)
    raise ApiError(422, "terraform_only",
                   "AWS cost analysis only uses the scanned repository's Terraform. External dumps cannot be selected.")


@router.post("/{project_id}/aws/dump", status_code=status.HTTP_201_CREATED)
async def upload_aws_dump(project_id: str, request: Request, file: UploadFile = File(...),
                          db: Session = Depends(get_db), principal: Principal = Depends(require("project:create")),
                          c: Container = Depends(container)) -> dict:
    load_project(db, principal, project_id, request)
    raise ApiError(422, "terraform_only",
                   "AWS cost analysis generates its own dump from the scanned repository's Terraform; uploads are disabled.")
