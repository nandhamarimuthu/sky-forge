from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.agents import AGENTS
from app.agents.base import TOOL_NAMES
from app.api.deps import accessible_project_ids, client_ip, container, get_principal, require
from app.core.errors import ApiError
from app.core.security import Principal
from app.db.session import get_db
from app.models import AgentRun, AuditEvent, Finding, Project, Scan, Setting, TestRun
from app.schemas.api import AgentRunOut, AuditOut, Page, SettingsUpdate, TestRunOut
from app.services.audit import audit
from app.services.container import Container
from app.services.llm import PROVIDERS
from app.services.publish import github_auth_mode, publish_enabled
from app.services.reset import wipe_all
from app.services.views import OPEN_STATUSES, aws_adapter_for, project_quality_metrics, scan_out

router = APIRouter(tags=["platform"])


@router.get("/health")
def health(db: Session = Depends(get_db), c: Container = Depends(container)) -> dict[str, Any]:
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:  # noqa: BLE001
        db_ok = False
    llm = c.llm.status()
    return {"status": "ok" if db_ok else "degraded", "version": "0.1.0", "database": db_ok,
            "llm": {"reachable": llm["reachable"], "model_available": llm["model_available"], "model": llm["model"],
                    "provider": llm["provider"], "crewai_installed": llm["crewai_installed"]},
            "sandbox": c.sandbox.available(), "aws_mode": "terraform",
            "github_publish": publish_enabled(c), "github_token_env": c.settings.github_token_env,
            "github_auth": github_auth_mode(c)}


@router.get("/dashboard/summary")
def dashboard(db: Session = Depends(get_db), principal: Principal = Depends(get_principal),
              c: Container = Depends(container)) -> dict[str, Any]:
    ids = accessible_project_ids(db, principal)
    projects = db.execute(select(Project).where(Project.id.in_(ids))).scalars().all()
    open_f = [Finding.project_id.in_(ids), Finding.status.in_(OPEN_STATUSES)]
    by_sev: dict[str, int] = {k: v for k, v in db.execute(
        select(Finding.severity, func.count()).where(*open_f).group_by(Finding.severity)).all()}
    by_agent: dict[str, int] = {k: v for k, v in db.execute(select(Finding.source_agent, func.count()).where(*open_f)
                                                            .group_by(Finding.source_agent)).all()}
    by_category: dict[str, int] = {k: v for k, v in db.execute(select(Finding.category, func.count()).where(*open_f)
                                                               .group_by(Finding.category)).all()}
    by_status: dict[str, int] = {k: v for k, v in db.execute(select(Finding.status, func.count())
                                                             .where(Finding.project_id.in_(ids))
                                                             .group_by(Finding.status)).all()}
    savings = db.execute(select(func.coalesce(func.sum(Finding.estimated_monthly_savings), 0.0)).where(*open_f)
                         ).scalar_one()
    assert savings is not None  # coalesce(..., 0.0) never yields NULL

    coverage, health, spend, simulated = [], [], 0.0, False
    spend_series: dict[str, float] = defaultdict(float)
    per_project = []
    for p in projects:
        last = db.execute(select(Scan).where(Scan.project_id == p.id, Scan.status.in_(["completed", "partial"]))
                          .order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
        quality = project_quality_metrics(db, p.id)
        cov = quality["coverage"]
        if cov is not None:
            coverage.append(cov)
        if quality["health_score"] is not None:
            health.append(quality["health_score"])
        adapter = aws_adapter_for(c, db, p)
        cost = adapter.cost(60)
        p_spend = None
        if cost:
            daily: dict[str, float] = defaultdict(float)
            for pts in cost.by_service.values():
                for day, value in pts:
                    daily[day] += value
                    spend_series[day] += value
            p_spend = round(sum(value for _, value in sorted(daily.items())[-30:]), 2)
            spend += p_spend
            simulated = simulated or adapter.report.simulated
        per_project.append({"id": p.id, "name": p.name, "coverage": cov,
                            "health_score": quality["health_score"], "spend_30d": p_spend,
                            "open": db.execute(select(func.count()).where(Finding.project_id == p.id,
                                                                          Finding.status.in_(OPEN_STATUSES))
                                               ).scalar_one(),
                            "last_scan_status": last.status if last else None})

    tests = db.execute(select(TestRun).where(TestRun.project_id.in_(ids)).order_by(TestRun.created_at.desc())
                       .limit(200)).scalars().all()
    latest_by_proj_kind: dict[tuple[str, str], TestRun] = {}
    for t in tests:
        latest_by_proj_kind.setdefault((t.project_id, t.kind), t)
    test_totals = {"passed": 0, "failed": 0, "errors": 0, "total": 0, "not_executed": 0}
    for t in latest_by_proj_kind.values():
        if t.status == "not_executed":
            test_totals["not_executed"] += 1
        test_totals["passed"] += t.passed
        test_totals["failed"] += t.failed
        test_totals["errors"] += t.errors
        test_totals["total"] += t.total

    recent = db.execute(select(Scan).where(Scan.project_id.in_(ids)).order_by(Scan.created_at.desc()).limit(8)
                        ).scalars().all()
    names = {p.id: p.name for p in projects}
    trend_rows = db.execute(select(Scan).where(Scan.project_id.in_(ids), Scan.status.in_(["completed", "partial"]))
                            .order_by(Scan.created_at).limit(60)).scalars().all()
    trend = [{"scan_id": s.id, "project": names.get(s.project_id), "date": s.finished_at,
              "findings": (s.summary or {}).get("findings", 0),
              "critical": (s.summary or {}).get("by_severity", {}).get("critical", 0),
              "high": (s.summary or {}).get("by_severity", {}).get("high", 0),
              "health_score": (s.summary or {}).get("health_score"),
              "coverage": ((s.summary or {}).get("coverage_after") if (s.summary or {}).get("coverage_after") is not None
                           else (s.summary or {}).get("coverage"))}
             for s in trend_rows]
    top = db.execute(select(Finding).where(*open_f).order_by(
        func.coalesce(Finding.estimated_monthly_savings, 0).desc()).limit(200)).scalars().all()
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    top = sorted(top, key=lambda f: (-rank.get(f.severity, 0), -(f.estimated_monthly_savings or 0)))[:10]

    agent_activity = []
    for a in AGENTS.values():
        last_run = db.execute(select(AgentRun).where(AgentRun.project_id.in_(ids), AgentRun.agent_id == a.id)
                              .order_by(AgentRun.started_at.desc().nullslast()).limit(1)).scalar_one_or_none()
        running = db.execute(select(func.count()).where(AgentRun.project_id.in_(ids), AgentRun.agent_id == a.id,
                                                        AgentRun.status == "running")).scalar_one()
        agent_activity.append({"id": a.id, "name": a.name, "code": a.code, "running": running,
                               "open_findings": by_agent.get(a.id, 0),
                               "last_status": last_run.status if last_run else None,
                               "last_run": last_run.finished_at or last_run.started_at if last_run else None})
    return {
        "projects": len(projects), "open_by_severity": by_sev, "open_total": sum(by_sev.values()),
        "critical_high": by_sev.get("critical", 0) + by_sev.get("high", 0), "by_status": by_status,
        "open_by_category": by_category,
        "vulnerabilities": by_category.get("vulnerability", 0),
        "coverage_avg": round(sum(coverage) / len(coverage), 1) if coverage else None,
        "health_avg": round(sum(health) / len(health)) if health else None,
        "tests": test_totals, "spend_30d": round(spend, 2), "spend_simulated": simulated,
        "estimated_monthly_savings": round(savings, 2), "per_project": per_project,
        "recent_scans": [scan_out(db, s, with_runs=True, project_name=names.get(s.project_id)) for s in recent],
        "trend": trend, "agent_activity": agent_activity,
        "spend_series": [{"date": d, "cost": round(v, 2)} for d, v in sorted(spend_series.items())],
        "top_actions": [{"id": f.id, "title": f.title, "severity": f.severity, "agent": f.source_agent,
                         "project": names.get(f.project_id), "savings": f.estimated_monthly_savings,
                         "status": f.status, "category": f.category, "has_proposal": bool(f.proposals)} for f in top],
    }


@router.get("/aws/dumps")
def aws_dumps(principal: Principal = Depends(get_principal), c: Container = Depends(container)) -> list[dict[str, Any]]:
    return []


@router.get("/agents")
def list_agents(db: Session = Depends(get_db), principal: Principal = Depends(get_principal),
                c: Container = Depends(container)) -> list[dict[str, Any]]:
    ids = accessible_project_ids(db, principal)
    out = []
    llm_ok = c.llm.usable
    for a in AGENTS.values():
        counts: dict[str, int] = {k: v for k, v in db.execute(select(AgentRun.status, func.count()).where(
            AgentRun.agent_id == a.id, AgentRun.project_id.in_(ids)).group_by(AgentRun.status)).all()}
        open_f = db.execute(select(func.count()).where(Finding.source_agent == a.id, Finding.project_id.in_(ids),
                                                       Finding.status.in_(OPEN_STATUSES))).scalar_one()
        avail = []
        for t in sorted(a.allowed_tools):
            ok = True
            if t == "sandbox.execute":
                ok = c.sandbox.available()
            elif t == "llm.generate":
                ok = llm_ok
            avail.append({"name": t, "description": TOOL_NAMES.get(t, t), "available": ok})
        out.append({**a.meta(), "tools": avail, "runs_by_status": counts, "open_findings": open_f,
                    "status": "running" if counts.get("running") else ("queued" if counts.get("queued") else "idle")})
    return out


@router.get("/agents/{agent_id}/runs", response_model=Page[AgentRunOut])
def agent_runs(agent_id: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
               db: Session = Depends(get_db), principal: Principal = Depends(get_principal)) -> Page[AgentRunOut]:
    if agent_id not in AGENTS:
        raise ApiError(404, "not_found", "Unknown agent")
    ids = accessible_project_ids(db, principal)
    stmt = select(AgentRun).where(AgentRun.agent_id == agent_id, AgentRun.project_id.in_(ids))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(AgentRun.started_at.desc().nullsfirst()).offset((page - 1) * page_size)
                      .limit(page_size)).scalars()
    return Page(items=[AgentRunOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)


@router.get("/test-runs")
def test_runs(project_id: str | None = Query(None, max_length=40), page_size: int = Query(100, ge=1, le=500),
              db: Session = Depends(get_db), principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    ids = accessible_project_ids(db, principal)
    if project_id:
        ids = [i for i in ids if i == project_id]
    rows = db.execute(select(TestRun).where(TestRun.project_id.in_(ids)).order_by(TestRun.created_at.desc())
                      .limit(page_size)).scalars().all()
    history = db.execute(select(AgentRun).where(AgentRun.project_id.in_(ids), AgentRun.agent_id == "unit_test",
                                                AgentRun.status == "completed").order_by(AgentRun.finished_at)
                         ).scalars().all()
    names: dict[str, str] = {k: v for k, v in db.execute(select(Project.id, Project.name)).all()}
    gaps = db.execute(select(Finding).where(Finding.project_id.in_(ids), Finding.category.in_(["coverage",
                                                                                              "functional"]),
                                            Finding.status.in_(OPEN_STATUSES)).limit(200)).scalars().all()
    return {"runs": [{**TestRunOut.model_validate(r).model_dump(mode="json"), "project_name": names.get(r.project_id)}
                     for r in rows],
            "coverage_history": [{"date": r.finished_at, "project": names.get(r.project_id), "scan_id": r.scan_id,
                                  "before": (r.metrics or {}).get("coverage_before"),
                                  "after": (r.metrics or {}).get("coverage_after"),
                                  "generated": (r.metrics or {}).get("tests_generated", 0)} for r in history],
            "gaps": [{"id": f.id, "title": f.title, "severity": f.severity, "project": names.get(f.project_id),
                      "target": f.target, "category": f.category, "evidence": f.evidence,
                      "has_proposal": bool(f.proposals)} for f in gaps]}


@router.get("/settings")
def get_settings_view(db: Session = Depends(get_db), principal: Principal = Depends(get_principal),
                      c: Container = Depends(container)) -> dict[str, Any]:
    stored = {s.key: s.value for s in db.execute(select(Setting)).scalars()}
    llm = c.llm.status()
    return {
        "llm": {**llm, "model": c.llm.model, "enabled": c.llm.enabled, "provider": c.llm.provider,
                "providers": list(PROVIDERS)},
        "scan_policy": {"default_agents": list(AGENTS), "execute_tests": True, "auto_generate_tests": True,
                        "agent_timeout_s": c.settings.agent_timeout_s, "max_repo_mb": c.settings.max_repo_mb,
                        **(stored.get("scan_policy") or {})},
        "integrations": {"osv": c.settings.osv_api_url, "docker_sandbox": c.sandbox.available(),
                         "sandbox_image": c.settings.sandbox_python_image, "aws_mode": "terraform",
                         "aws_regions": c.settings.region_allowlist, "aws_services": c.settings.service_allowlist,
                         "git_hosts": c.settings.git_hosts, "github_publish": publish_enabled(c),
                         "github_token_env": c.settings.github_token_env, "github_auth": github_auth_mode(c)},
        "principal": {"name": principal.name, "role": principal.role, "projects": sorted(principal.projects),
                      "permissions": sorted({p for p in ("read", "project:create", "scan:run", "finding:review",
                                                         "remediation:approve", "remediation:apply", "settings:write",
                                                         "audit:read", "project:delete") if principal.can(p)})},
        "agents": [a.meta() for a in AGENTS.values()],
    }


@router.put("/settings")
def update_settings(body: SettingsUpdate, request: Request, db: Session = Depends(get_db),
                    principal: Principal = Depends(require("settings:write")),
                    c: Container = Depends(container)) -> dict[str, Any]:
    changes = body.model_dump(exclude_none=True)
    if "llm_provider" in changes:
        c.llm.provider = changes["llm_provider"]
    if "ollama_model" in changes:
        c.llm.ollama_model = changes["ollama_model"]
    if "openai_model" in changes:
        c.llm.openai_model = changes["openai_model"]
    if "llm_enabled" in changes:
        c.llm.enabled = changes["llm_enabled"]
    if changes.keys() & {"llm_provider", "ollama_model", "openai_model", "llm_enabled"}:
        c.llm.status(force=True)
    policy_keys = {"default_agents", "execute_tests", "auto_generate_tests"}
    policy = {k: v for k, v in changes.items() if k in policy_keys}
    if policy:
        row = db.get(Setting, "scan_policy") or Setting(key="scan_policy", value={})
        row.value = {**(row.value or {}), **policy}
        row.updated_by = principal.name
        db.add(row)
    llm_keys = {k: v for k, v in changes.items()
                if k in ("llm_provider", "ollama_model", "openai_model", "llm_enabled")}
    if llm_keys:
        row = db.get(Setting, "llm") or Setting(key="llm", value={})
        row.value = {**(row.value or {}), **llm_keys}
        row.updated_by = principal.name
        db.add(row)
    if "openai_api_key" in changes:
        c.llm.set_api_key(changes["openai_api_key"])
        row = db.get(Setting, "llm_secrets") or Setting(key="llm_secrets", value={})
        row.value = {**(row.value or {}), "openai_api_key": c.llm.api_key_override}
        row.updated_by = principal.name
        db.add(row)
    audit(db, principal.name, "settings.update", "settings", "global", "allowed",
          {**changes, **({"openai_api_key": "set" if changes["openai_api_key"] else "cleared"}
                         if "openai_api_key" in changes else {})}, client_ip(request))
    return get_settings_view(db, principal, c)


class ResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: str = Field(max_length=40)


RESET_PHRASE = "DELETE ALL DATA"


@router.post("/admin/reset")
def reset_all_data(body: ResetRequest, request: Request, db: Session = Depends(get_db),
                   principal: Principal = Depends(require("settings:write")),
                   c: Container = Depends(container)) -> dict[str, Any]:
    if body.confirm != RESET_PHRASE:
        raise ApiError(400, "confirmation_required", f'Type "{RESET_PHRASE}" to confirm')
    c.worker.cancel_all()
    deadline = time.monotonic() + 30
    while c.worker.active() and time.monotonic() < deadline:
        time.sleep(0.5)
    if c.worker.active():
        raise ApiError(409, "scans_still_running", "Scans are still stopping - try again in a few seconds")
    result = wipe_all(db, c.settings)
    audit(db, principal.name, "platform.reset", "platform", "all", "allowed", result, client_ip(request))
    return result


@router.get("/audit", response_model=Page[AuditOut])
def audit_log(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
              outcome: str | None = Query(None, max_length=16), action: str | None = Query(None, max_length=80),
              db: Session = Depends(get_db), principal: Principal = Depends(require("audit:read"))) -> Page[AuditOut]:
    stmt = select(AuditEvent)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if action:
        stmt = stmt.where(AuditEvent.action.ilike(f"{action}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(AuditEvent.id.desc()).offset((page - 1) * page_size).limit(page_size)).scalars()
    return Page(items=[AuditOut.model_validate(r) for r in rows], total=total, page=page, page_size=page_size)
