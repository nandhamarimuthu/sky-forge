"""Central Scan Orchestrator.

Steps: validate → create workspace → collect evidence → dispatch agents (concurrently, with timeouts, bounded
retries and failure isolation) → schema-validate outputs → dedupe/normalise → guardrail validation of every
proposal → persist findings/logs/artifacts/test runs → LLM explanations (optional) → publish final status.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import traceback
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError
from sqlalchemy import select

from app.adapters.aws.factory import build_aws_adapter
from app.adapters.repository.git_repo import RepositoryError, RepoWorkspace, materialize, parse_repo_url
from app.adapters.sandbox import DockerSandbox
from app.adapters.scanners.manifests import upgrade_patch
from app.adapters.scanners.osv import OSVClient
from app.adapters.scanners.terraform import parse_terraform
from app.agents import AGENTS
from app.agents.base import AgentContext, CancelledError, ToolPermissionError
from app.agents.security_guardrails import PolicyEngine
from app.core.config import Settings, secret_from_env
from app.core.security import redact
from app.db.session import session_scope
from app.models import (
    AgentRun,
    Finding,
    Project,
    RemediationProposal,
    Scan,
    ScanArtifact,
    ScanEvent,
    TestRun,
    utcnow,
)
from app.orchestration.crew import explain_with_crew, template_explanation
from app.schemas.agents import SEVERITY_RANK, AgentResult, FindingDraft
from app.services.audit import audit
from app.services.llm import LLMService

log = logging.getLogger(__name__)
TERMINAL = {"completed", "partial", "failed", "cancelled"}
RETRYABLE = (httpx.TransportError, TimeoutError, ConnectionError)


def finding_id(project_id: str, agent: str, rule: str, key: str) -> tuple[str, str]:
    fp = hashlib.sha256(f"{agent}|{rule}|{key}".encode()).hexdigest()
    return "F-" + hashlib.sha256(f"{project_id}|{fp}".encode()).hexdigest()[:14].upper(), fp


def workspace_dir(settings: Settings, project_id: str, scan_id: str) -> Path:
    return settings.workspaces_dir / project_id / scan_id


class EventSink:
    """Writes scan events to the DB (durable, replayable by SSE clients)."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self._agent_progress: dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_progress_write = 0.0
        self.base = 0.0

    def emit(self, type_: str, message: str = "", *, agent_id: str | None = None, level: str = "info",
             progress: float | None = None, data: dict[str, Any] | None = None) -> None:
        overall = None
        with self._lock:
            if agent_id and progress is not None:
                self._agent_progress[agent_id] = progress
            if self._agent_progress:
                overall = round(0.1 + 0.8 * sum(self._agent_progress.values()) / len(self._agent_progress), 3)
        with session_scope() as db:
            db.add(ScanEvent(scan_id=self.scan_id, type=type_, agent_id=agent_id, level=level,
                             message=redact(message)[:2000], progress=progress,
                             data=json.loads(json.dumps(data or {}, default=str))))
            now = time.monotonic()
            if overall is not None and (now - self._last_progress_write > 0.5 or type_ != "agent.progress"):
                self._last_progress_write = now
                scan = db.get(Scan, self.scan_id)
                if scan and scan.status == "running":
                    scan.progress = max(scan.progress, overall)
            if agent_id and progress is not None:
                run = db.execute(select(AgentRun).where(AgentRun.scan_id == self.scan_id,
                                                        AgentRun.agent_id == agent_id)).scalar_one_or_none()
                if run:
                    run.progress = progress

    def register(self, agent_ids: list[str]) -> None:
        with self._lock:
            self._agent_progress = {a: 0.0 for a in agent_ids}


class DeferredSink:
    """Buffers events raised while a write transaction is open (SQLite allows a single writer)."""

    def __init__(self) -> None:
        self.items: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def emit(self, *args: Any, **kwargs: Any) -> None:
        self.items.append((args, kwargs))

    def replay(self, sink: EventSink) -> None:
        for args, kwargs in self.items:
            sink.emit(*args, **kwargs)


class ScanOrchestrator:
    def __init__(self, settings: Settings, llm: LLMService, sandbox: DockerSandbox, osv: OSVClient):
        self.settings = settings
        self.llm = llm
        self.sandbox = sandbox
        self.osv = osv

    # ------------------------------------------------------------------ main entry
    def run(self, scan_id: str, cancel: threading.Event) -> None:
        sink = EventSink(scan_id)
        try:
            self._run(scan_id, cancel, sink)
        except CancelledError:
            self._finish(scan_id, "cancelled", sink, error="Cancelled by user")
        except Exception as exc:  # noqa: BLE001 - never leave a scan stuck in 'running'
            log.exception("Scan %s crashed", scan_id)
            self._finish(scan_id, "failed", sink, error=f"{type(exc).__name__}: {redact(str(exc))[:500]}")

    def _run(self, scan_id: str, cancel: threading.Event, sink: EventSink) -> None:
        # 1. Validate
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.status != "queued":
                return
            project = db.get(Project, scan.project_id)
            if project is None or project.repository is None:
                raise RuntimeError("Project or repository connection missing")
            agent_ids = [a for a in scan.agents if a in AGENTS]
            if not agent_ids:
                raise RuntimeError("No valid agents requested")
            acct = project.cloud_account
            if acct:
                bad = [r for r in acct.regions if r not in self.settings.region_allowlist]
                if bad:
                    raise RuntimeError(f"Regions not in allowlist: {bad}")
            scan.status, scan.started_at, scan.progress = "running", utcnow(), 0.02
            snapshot: dict[str, Any] = {
                "id": project.id, "name": project.name,
                "repo_url": project.repository.url, "branch": project.repository.branch,
                "token_ref": project.repository.token_secret_ref,
                "aws": ({"account_id": acct.account_id, "project_tag": acct.project_tag, "regions": acct.regions,
                         "mode": acct.mode} if acct else None),
            }
            options = dict(scan.options or {})
            for a in agent_ids:
                db.add(AgentRun(scan_id=scan_id, project_id=project.id, agent_id=a, status="queued"))
        sink.emit("scan.status", f"Scan started with {len(agent_ids)} agent(s)", data={"status": "running"})

        # 2–3. Workspace + repository evidence
        ws_root = workspace_dir(self.settings, snapshot["id"], scan_id) / "repo"
        sink.emit("scan.log", f"Fetching repository {snapshot['repo_url']}")
        try:
            ref = parse_repo_url(snapshot["repo_url"], self.settings.git_hosts, self.settings.fixtures_dir)
            token = secret_from_env(snapshot["token_ref"])
            commit = materialize(ref, ws_root, branch=snapshot["branch"], fixtures_dir=self.settings.fixtures_dir,
                                 timeout=self.settings.clone_timeout_s, max_mb=self.settings.max_repo_mb, token=token)
        except RepositoryError as exc:
            with session_scope() as db:
                for run in db.execute(select(AgentRun).where(AgentRun.scan_id == scan_id)).scalars():
                    run.status, run.error = "skipped", "Repository unavailable"
            self._finish(scan_id, "failed", sink, error=str(exc))
            return
        ws = RepoWorkspace(ws_root)
        langs = ws.languages()
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            assert scan is not None
            scan.commit_sha = commit
            scan.progress = 0.1
            proj = db.get(Project, snapshot["id"])
            if proj and proj.repository:
                proj.repository.last_commit = commit
                if proj.language == "auto":
                    proj.language = ws.primary_language()
        sink.emit("scan.log", f"Checked out {commit[:10]} — languages: {langs}", data={"commit": commit,
                                                                                    "languages": langs})
        cancel_check(cancel)

        # 4. Dispatch agents
        sink.register(agent_ids)
        results = self._dispatch(scan_id, agent_ids, snapshot, ws, options, cancel, sink)
        cancel_check(cancel)

        # 5–9. Validate, dedupe, guardrails, persist, explain
        sink.emit("scan.log", "Validating agent output and proposals through security guardrails")
        persisted = self._persist(scan_id, snapshot["id"], ws, results, sink)
        if options.get("use_llm", True) and self.llm.enabled:
            self._explain(persisted, sink)
        statuses = self._agent_statuses(scan_id)
        if all(s == "completed" for s in statuses.values()):
            final = "completed"
        elif any(s == "completed" for s in statuses.values()):
            final = "partial"
        else:
            final = "failed"
        self._finish(scan_id, final, sink)

    # ------------------------------------------------------------------ agents
    def _tools(self, snapshot: dict[str, Any], ws: RepoWorkspace) -> dict[str, Any]:
        settings = self.settings

        def aws_factory(hints: list[dict] | None = None) -> Any:
            with session_scope() as db:
                proj = db.get(Project, snapshot["id"])
                account = proj.cloud_account if proj else None
                return build_aws_adapter(settings, account, hints)

        return {"repo.read": ws, "osv.query": self.osv, "manifest.patch": upgrade_patch,
                "sandbox.execute": self.sandbox, "static.ruff": True, "static.radon": True,
                "terraform.parse": parse_terraform, "aws.read": aws_factory, "llm.generate": self.llm}

    def _dispatch(self, scan_id: str, agent_ids: list[str], snapshot: dict[str, Any], ws: RepoWorkspace,
                  options: dict[str, Any], cancel: threading.Event, sink: EventSink) -> dict[str, AgentResult]:
        tools = self._tools(snapshot, ws)
        results: dict[str, AgentResult] = {}
        per_agent_cancel = {a: threading.Event() for a in agent_ids}

        def watch() -> None:
            while not all(e.is_set() for e in per_agent_cancel.values()):
                if cancel.wait(0.5):
                    for e in per_agent_cancel.values():
                        e.set()
                    return

        threading.Thread(target=watch, daemon=True).start()

        def execute(agent_id: str) -> AgentResult:
            agent = AGENTS[agent_id]

            def emit(type_: str, message: str = "", **kw: Any) -> None:
                sink.emit(type_, message, agent_id=agent_id, **kw)

            ctx = AgentContext(scan_id=scan_id, project=snapshot, workspace=ws, options=options, tools=tools,
                               allowed_tools=agent.allowed_tools, emit=emit, cancel_event=per_agent_cancel[agent_id],
                               agent_id=agent_id)
            attempts = 0
            while True:
                attempts += 1
                self._set_run(scan_id, agent_id, status="running", attempts=attempts, started_at=utcnow())
                emit("agent.status", f"{agent.name} started (attempt {attempts})", data={"status": "running"})
                try:
                    res = agent.run(ctx)
                    res.tools_used = sorted(set(res.tools_used) | ctx.used_tools)
                    return AgentResult.model_validate(res.model_dump())
                except RETRYABLE as exc:
                    if attempts >= 2:
                        raise
                    emit("agent.log", f"Transient error ({type(exc).__name__}); retrying", level="warning")
                    time.sleep(2)

        pool = ThreadPoolExecutor(max_workers=min(4, len(agent_ids)), thread_name_prefix=f"agents-{scan_id[-6:]}")
        futures: dict[str, Future[AgentResult]] = {a: pool.submit(execute, a) for a in agent_ids}
        deadline = time.monotonic() + self.settings.agent_timeout_s
        for agent_id, fut in futures.items():
            try:
                res = fut.result(timeout=max(1.0, deadline - time.monotonic()))
                results[agent_id] = res
                status = "completed" if res.status == "completed" else ("failed" if res.status == "failed"
                                                                         else "partial")
                self._set_run(scan_id, agent_id, status="completed" if status == "partial" else status,
                              progress=1.0, finished_at=utcnow(), metrics=res.metrics, tools_used=res.tools_used,
                              findings_count=len(res.findings),
                              error="; ".join(res.notes)[:1000] if status == "partial" else None)
                sink.emit("agent.status", f"{AGENTS[agent_id].name} {status}: {len(res.findings)} finding(s)",
                          agent_id=agent_id, progress=1.0, data={"status": status, "findings": len(res.findings),
                                                                 "notes": res.notes[:5]})
            except FutureTimeout:
                per_agent_cancel[agent_id].set()
                self._set_run(scan_id, agent_id, status="timed_out", finished_at=utcnow(),
                              error=f"Exceeded {self.settings.agent_timeout_s}s")
                sink.emit("agent.status", f"{AGENTS[agent_id].name} timed out", agent_id=agent_id, level="error",
                          progress=1.0, data={"status": "timed_out"})
            except CancelledError:
                self._set_run(scan_id, agent_id, status="cancelled", finished_at=utcnow())
                sink.emit("agent.status", f"{AGENTS[agent_id].name} cancelled", agent_id=agent_id, progress=1.0,
                          data={"status": "cancelled"})
            except (ValidationError, ToolPermissionError, Exception) as exc:  # noqa: BLE001 - isolate failures
                msg = f"{type(exc).__name__}: {redact(str(exc))[:400]}"
                log.warning("Agent %s failed: %s\n%s", agent_id, msg, traceback.format_exc(limit=4))
                self._set_run(scan_id, agent_id, status="failed", finished_at=utcnow(), error=msg)
                sink.emit("agent.status", f"{AGENTS[agent_id].name} failed — {msg}", agent_id=agent_id,
                          level="error", progress=1.0, data={"status": "failed"})
        for e in per_agent_cancel.values():
            e.set()
        pool.shutdown(wait=False, cancel_futures=True)
        return results

    @staticmethod
    def _set_run(scan_id: str, agent_id: str, **fields: Any) -> None:
        with session_scope() as db:
            run = db.execute(select(AgentRun).where(AgentRun.scan_id == scan_id, AgentRun.agent_id == agent_id)
                             ).scalar_one_or_none()
            if run:
                for k, v in fields.items():
                    setattr(run, k, v)

    @staticmethod
    def _agent_statuses(scan_id: str) -> dict[str, str]:
        with session_scope() as db:
            return {r.agent_id: r.status for r in db.execute(select(AgentRun).where(AgentRun.scan_id == scan_id))
                    .scalars()}

    # ------------------------------------------------------------------ persistence
    def _persist(self, scan_id: str, project_id: str, ws: RepoWorkspace, results: dict[str, AgentResult],
                 sink: EventSink) -> list[dict[str, Any]]:
        policy = PolicyEngine(ws)
        art_dir = self.settings.artifacts_dir / scan_id
        art_dir.mkdir(parents=True, exist_ok=True)
        persisted: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        cross_agent: dict[tuple[str, str], str] = {}
        deferred = DeferredSink()
        with session_scope() as db:
            for agent_id, res in results.items():
                for art in res.artifacts:
                    self._artifact(db, scan_id, project_id, agent_id, art.kind, art.name, art.content, art.media_type,
                                   art_dir)
                for tr in res.test_runs:
                    report_id = None
                    if tr.report_content:
                        report_id = self._artifact(db, scan_id, project_id, agent_id, "report",
                                                   tr.report_name or f"{agent_id}-{tr.kind}.log", tr.report_content,
                                                   "text/plain", art_dir).id
                    db.add(TestRun(scan_id=scan_id, project_id=project_id, agent_id=agent_id, kind=tr.kind,
                                   framework=tr.framework, status=tr.status, total=tr.total, passed=tr.passed,
                                   failed=tr.failed, errors=tr.errors, skipped=tr.skipped,
                                   coverage_before=tr.coverage_before, coverage_after=tr.coverage_after,
                                   duration_s=tr.duration_s, details=tr.details, report_artifact_id=report_id))
                drafts = sorted(res.findings, key=lambda d: -SEVERITY_RANK[d.severity])
                drafts = drafts[: self.settings.max_findings_per_agent]
                for d in drafts:
                    fid, fp = finding_id(project_id, agent_id, d.rule_id, d.fingerprint_key)
                    if fid in seen_ids:
                        continue
                    xkey = (d.target, str(d.location.get("line", "")))
                    if d.category in ("secret", "security_policy"):
                        if xkey in cross_agent:
                            continue
                        cross_agent[xkey] = fid
                    seen_ids.add(fid)
                    persisted.append(self._upsert_finding(db, scan_id, project_id, agent_id, fid, fp, d, policy,
                                                          deferred))
            # Close out findings not re-detected by agents that completed successfully.
            completed = [a for a, r in results.items() if r.status in ("completed", "partial")]
            if completed:
                stale = db.execute(select(Finding).where(Finding.project_id == project_id,
                                                         Finding.source_agent.in_(completed),
                                                         Finding.status.in_(["open", "accepted", "in_progress",
                                                                             "fixed"]))).scalars()
                for f in stale:
                    if f.id in seen_ids:
                        continue
                    previously_fixed = f.status == "fixed"
                    f.status = "verified" if previously_fixed else "fixed"
                    f.validation = {**(f.validation or {}), "closed_by_scan": scan_id,
                                    "reason": "No longer detected by a successful re-scan"}
        deferred.replay(sink)
        sink.emit("scan.log", f"Persisted {len(persisted)} finding(s)")
        return persisted

    def _artifact(self, db: Any, scan_id: str, project_id: str, agent_id: str | None, kind: str, name: str,
                  content: str, media_type: str, art_dir: Path) -> ScanArtifact:
        art = ScanArtifact(scan_id=scan_id, project_id=project_id, agent_id=agent_id, kind=kind, name=name,
                           rel_path="", media_type=media_type, size=len(content.encode()))
        db.add(art)
        db.flush()
        rel = f"{scan_id}/{art.id}_{name}"
        (self.settings.artifacts_dir / rel).write_text(redact(content), encoding="utf-8")
        art.rel_path = rel
        return art

    def _upsert_finding(self, db: Any, scan_id: str, project_id: str, agent_id: str, fid: str, fp: str,
                        d: FindingDraft, policy: PolicyEngine, sink: DeferredSink) -> dict[str, Any]:
        f = db.get(Finding, fid)
        now = utcnow()
        fields = dict(scan_id=scan_id, source_agent=agent_id, category=d.category, rule_id=d.rule_id,
                      severity=d.severity, title=d.title, description=d.description, evidence=d.evidence,
                      target=d.target, location=d.location, recommendation=d.recommendation, confidence=d.confidence,
                      data_source=d.data_source, estimated_monthly_savings=d.estimated_monthly_savings,
                      last_seen_at=now)
        if f is None:
            f = Finding(id=fid, project_id=project_id, first_scan_id=scan_id, fingerprint=fp, status="open", **fields)
            db.add(f)
        else:
            for k, v in fields.items():
                setattr(f, k, v)
            if f.status in ("fixed", "verified"):
                f.status = "open"
                f.validation = {**(f.validation or {}), "regressed_in_scan": scan_id}
                sink.emit("scan.log", f"Regression: {fid} detected again", level="warning", agent_id=agent_id)
        db.flush()
        if d.proposal:
            for old in list(f.proposals):
                if old.status in ("proposed", "validated", "rejected_by_policy", "declined"):
                    db.delete(old)
            validation = policy.validate(d.proposal)
            if d.proposal.codemod:
                validation["codemod"] = d.proposal.codemod
            prop = RemediationProposal(
                finding_id=fid, project_id=project_id, scan_id=scan_id, agent_id=agent_id, kind=d.proposal.kind,
                title=d.proposal.title, summary=d.proposal.summary, diff=redact(d.proposal.diff),
                files=d.proposal.files, breaking=d.proposal.breaking,
                status="validated" if validation["passed"] else "rejected_by_policy", validation=validation)
            db.add(prop)
            if not validation["passed"]:
                failed = [c["name"] for c in validation["checks"] if not c["passed"]]
                sink.emit("agent.log", f"Guardrails rejected proposal for {fid}: {failed}", agent_id="guardrails",
                          level="warning", data={"finding": fid, "failed_checks": failed})
        evidence_summary = json.dumps(d.evidence, default=str)[:600]
        return {"id": fid, "source_agent": agent_id, "severity": d.severity, "title": d.title,
                "description": d.description, "recommendation": d.recommendation,
                "estimated_monthly_savings": d.estimated_monthly_savings, "data_source": d.data_source,
                "evidence_summary": evidence_summary}

    def _explain(self, persisted: list[dict[str, Any]], sink: EventSink) -> None:
        top = sorted(persisted, key=lambda f: -SEVERITY_RANK[f["severity"]])[:30]
        explanations: dict[str, str] = {}
        engine = "template"
        if self.llm.usable and top:
            sink.emit("scan.log", f"Generating explanations with {self.llm.resolved_model()} via CrewAI/Ollama")
            try:
                explanations, engine = explain_with_crew(self.llm, top)
            except Exception as exc:  # noqa: BLE001
                sink.emit("scan.log", f"LLM explanation failed: {type(exc).__name__}", level="warning")
        else:
            sink.emit("scan.log", "LLM unavailable — using deterministic explanations", level="info")
        with session_scope() as db:
            for f in persisted:
                row = db.get(Finding, f["id"])
                if row is None:
                    continue
                if f["id"] in explanations:
                    row.explanation, row.explanation_source = explanations[f["id"]], engine
                else:
                    row.explanation, row.explanation_source = template_explanation(f), "template"

    # ------------------------------------------------------------------ completion
    def _finish(self, scan_id: str, status: str, sink: EventSink, error: str | None = None) -> None:
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:
                return
            for run in db.execute(select(AgentRun).where(AgentRun.scan_id == scan_id)).scalars():
                if run.status in ("queued", "running"):
                    run.status = "cancelled" if status == "cancelled" else "failed"
                    run.finished_at = run.finished_at or utcnow()
            scan.status = status
            scan.finished_at = datetime.now(UTC)
            scan.progress = 1.0
            scan.error = error
            scan.summary = build_summary(db, scan_id)
            audit(db, scan.requested_by, "scan.finished", "scan", scan_id, "info",
                  {"status": status, "error": error}, commit=False)
        sink.emit("scan.status", f"Scan {status}" + (f": {error}" if error else ""), level="error" if status ==
                  "failed" else "info", data={"status": status, "terminal": True})


def cancel_check(cancel: threading.Event) -> None:
    if cancel.is_set():
        raise CancelledError("Scan cancelled")


def build_summary(db: Any, scan_id: str) -> dict[str, Any]:
    findings = db.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
    by_sev: dict[str, int] = {}
    by_agent: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_agent[f.source_agent] = by_agent.get(f.source_agent, 0) + 1
    runs = db.execute(select(AgentRun).where(AgentRun.scan_id == scan_id)).scalars().all()
    metrics = {r.agent_id: r.metrics for r in runs}
    return {"findings": len(findings), "by_severity": by_sev, "by_agent": by_agent,
            "estimated_monthly_savings": round(sum(f.estimated_monthly_savings or 0 for f in findings), 2),
            "agent_status": {r.agent_id: r.status for r in runs},
            "coverage": (metrics.get("unit_test") or {}).get("coverage_before"),
            "coverage_after": (metrics.get("unit_test") or {}).get("coverage_after"),
            "health_score": (metrics.get("code_health") or {}).get("health_score")}
