from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import ColumnElement, case, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import accessible_project_ids, client_ip, container, get_principal, load_project, require
from app.core.errors import ApiError
from app.core.security import Principal
from app.db.session import get_db
from app.models import Approval, Finding, Project, RemediationProposal, TestRun
from app.schemas.api import (
    ApprovalOut,
    FindingDetail,
    FindingOut,
    ProposalOut,
    RemediateRequest,
    ReviewRequest,
    TestRunOut,
)
from app.services import publish, remediation
from app.services.container import Container

router = APIRouter(prefix="/findings", tags=["findings"])
SEV_ORDER = case({"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}, value=Finding.severity, else_=0)


def _csv(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()][:10]


@router.get("")
def list_findings(project_id: str | None = Query(None, max_length=40), severity: str | None = Query(None),
                  status_: str | None = Query(None, alias="status"), agent: str | None = Query(None),
                  category: str | None = Query(None), q: str | None = Query(None, max_length=120),
                  data_source: str | None = Query(None),
                  sort: str = Query("severity", pattern="^(severity|created|updated|savings|title)$"),
                  order: str = Query("desc", pattern="^(asc|desc)$"), page: int = Query(1, ge=1),
                  page_size: int = Query(25, ge=1, le=200), db: Session = Depends(get_db),
                  principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    ids = accessible_project_ids(db, principal)
    if project_id:
        ids = [i for i in ids if i == project_id]
    filters: list[ColumnElement[bool]] = [Finding.project_id.in_(ids)]
    for col, raw in ((Finding.severity, severity), (Finding.status, status_), (Finding.source_agent, agent),
                     (Finding.category, category), (Finding.data_source, data_source)):
        vals = _csv(raw)
        if vals:
            filters.append(col.in_(vals))
    if q:
        like = f"%{q}%"
        filters.append(or_(Finding.title.ilike(like), Finding.target.ilike(like), Finding.rule_id.ilike(like),
                           Finding.id.ilike(like)))
    stmt = select(Finding).where(*filters)
    sort_col = {"severity": SEV_ORDER, "created": Finding.created_at, "updated": Finding.updated_at,
                "savings": func.coalesce(Finding.estimated_monthly_savings, 0), "title": Finding.title}[sort]
    stmt = stmt.order_by(sort_col.desc() if order == "desc" else sort_col.asc(), Finding.updated_at.desc())
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars().all()
    names: dict[str, str] = {k: v for k, v in db.execute(select(Project.id, Project.name)).all()}
    with_props = set(db.execute(select(RemediationProposal.finding_id).where(
        RemediationProposal.finding_id.in_([f.id for f in rows]))).scalars())
    items = []
    for f in rows:
        o = FindingOut.model_validate(f)
        o.has_proposal = f.id in with_props
        o.project_name = names.get(f.project_id)
        items.append(o)
    facets: dict[str, dict[str, int]] = {}
    base = [Finding.project_id.in_(ids)]
    for name, col in (("severity", Finding.severity), ("status", Finding.status), ("agent", Finding.source_agent),
                      ("category", Finding.category)):
        facets[name] = {k: v for k, v in db.execute(select(col, func.count()).where(*base).group_by(col)).all()}
    return {"items": items, "total": total, "page": page, "page_size": page_size, "facets": facets}


def _load(db: Session, principal: Principal, finding_id: str, request: Request) -> Finding:
    f = db.get(Finding, finding_id)
    if f is None:
        raise ApiError(404, "not_found", "Finding not found")
    load_project(db, principal, f.project_id, request)
    return f


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str, request: Request, db: Session = Depends(get_db),
                principal: Principal = Depends(get_principal)) -> FindingDetail:
    f = _load(db, principal, finding_id, request)
    out = FindingDetail.model_validate(f)
    out.proposals = [ProposalOut.model_validate(p) for p in f.proposals]
    out.has_proposal = bool(f.proposals)
    out.approvals = [ApprovalOut.model_validate(a) for a in db.execute(
        select(Approval).where(Approval.finding_id == f.id).order_by(Approval.created_at)).scalars()]
    out.test_runs = [TestRunOut.model_validate(t) for t in db.execute(
        select(TestRun).where(TestRun.scan_id == f.scan_id, TestRun.agent_id == f.source_agent)
        .order_by(TestRun.created_at)).scalars()]
    project = db.get(Project, f.project_id)
    out.project_name = project.name if project else None
    return out


@router.post("/{finding_id}/review", response_model=FindingDetail)
def review_finding(finding_id: str, body: ReviewRequest, request: Request, db: Session = Depends(get_db),
                   principal: Principal = Depends(require("finding:review")),
                   c: Container = Depends(container)) -> FindingDetail:
    f = _load(db, principal, finding_id, request)
    if body.decision in ("approve", "decline"):
        if not principal.can("remediation:approve"):
            raise ApiError(403, "forbidden", "Your role cannot approve remediations")
        prop = next((p for p in f.proposals if p.id == body.proposal_id), None)
        if prop is None:
            raise ApiError(404, "not_found", "Proposal not found for this finding")
        if body.decision == "approve":
            remediation.approve(db, c, f, prop, principal, body.comment, client_ip(request))
        else:
            remediation.decline(db, f, prop, principal, body.comment, client_ip(request))
    else:
        remediation.record_review(db, f, body.decision, principal, body.comment, client_ip(request))
    db.refresh(f)
    return get_finding(finding_id, request, db, principal)


@router.post("/{finding_id}/remediate", response_model=ProposalOut, status_code=status.HTTP_202_ACCEPTED)
def remediate(finding_id: str, body: RemediateRequest, request: Request, db: Session = Depends(get_db),
              principal: Principal = Depends(require("remediation:apply")),
              c: Container = Depends(container)) -> ProposalOut:
    f = _load(db, principal, finding_id, request)
    prop = next((p for p in f.proposals if p.id == body.proposal_id), None)
    if prop is None:
        raise ApiError(404, "not_found", "Proposal not found for this finding")
    remediation.start_apply(db, c, f, prop, principal, client_ip(request))
    return ProposalOut.model_validate(prop)


@router.post("/{finding_id}/fix", response_model=ProposalOut, status_code=status.HTTP_202_ACCEPTED)
def fix(finding_id: str, body: RemediateRequest, request: Request, db: Session = Depends(get_db),
        principal: Principal = Depends(require("remediation:apply")),
        c: Container = Depends(container)) -> ProposalOut:
    """One-click fix: approve, apply on an isolated branch, verify, then open a draft pull request."""
    f = _load(db, principal, finding_id, request)
    prop = next((p for p in f.proposals if p.id == body.proposal_id), None)
    if prop is None:
        raise ApiError(404, "not_found", "Proposal not found for this finding")
    if not publish.publish_enabled(c):
        raise ApiError(422, "github_token_missing",
                       f"Set {c.settings.github_token_env} on the server to let Fix open a pull request")
    remediation.one_click_fix(db, c, f, prop, principal, body.comment, client_ip(request))
    return ProposalOut.model_validate(prop)


@router.post("/{finding_id}/pull-request")
def pull_request(finding_id: str, body: RemediateRequest, request: Request, db: Session = Depends(get_db),
                 principal: Principal = Depends(require("remediation:apply")),
                 c: Container = Depends(container)) -> dict[str, Any]:
    f = _load(db, principal, finding_id, request)
    prop = next((p for p in f.proposals if p.id == body.proposal_id), None)
    if prop is None:
        raise ApiError(404, "not_found", "Proposal not found for this finding")
    return publish.open_pull_request(db, c, f, prop, principal, client_ip(request))
