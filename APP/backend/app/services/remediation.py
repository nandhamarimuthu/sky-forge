"""Remediation workflow: Detect → Explain → Propose → Validate → Approve → Apply → Verify.

- Approval requires a passing guardrail validation (re-run at approval time).
- Apply happens only in an isolated git worktree on a new local branch — never on a shared branch. Pushing it and
  opening a draft PR is a separate, explicit human action (see services/publish.py).
- Verification re-runs the relevant check; a fix is only marked `verified` when that check confirms it.
"""

from __future__ import annotations

import ast
import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from sqlalchemy.orm import Session

from app.adapters.repository.git_repo import RepositoryError, RepoWorkspace, run_git
from app.adapters.repository.patches import PatchReconstructionError, restore_patch_context
from app.adapters.scanners.code_metrics import JS_EXTS, RUFF_SAFE_FIX_RULES, ruff_binary
from app.adapters.scanners.js_refactor import verify_js_refactor
from app.adapters.scanners.manifests import discover_dependencies
from app.adapters.scanners.terraform import parse_terraform
from app.agents.security_guardrails import CODE_RULES, PolicyEngine, scan_secrets, secret_fix, syntax_check
from app.core.errors import ApiError
from app.core.security import Principal, redact
from app.db.session import session_scope
from app.models import Approval, Finding, RemediationProposal, Scan, ScanArtifact, TestRun, utcnow
from app.orchestration.orchestrator import workspace_dir
from app.services import publish
from app.services.audit import audit
from app.services.container import Container

log = logging.getLogger(__name__)


def scan_workspace(c: Container, prop: RemediationProposal) -> RepoWorkspace:
    root = workspace_dir(c.settings, prop.project_id, prop.scan_id) / "repo"
    if not (root / ".git").exists():
        raise ApiError(409, "workspace_missing", "The scan workspace for this proposal no longer exists; re-scan the "
                                                 "project to regenerate the fix.")
    return RepoWorkspace(root)


@dataclass
class Change:
    kind: str
    diff: str
    files: list[str]
    breaking: bool


def effective_change(prop: RemediationProposal, ws: RepoWorkspace) -> Change:
    """Rebuild redacted context in memory; the persisted and reviewed diff always stays redacted."""
    codemod = (prop.validation or {}).get("codemod")
    if not codemod:
        try:
            diff = restore_patch_context(ws, prop.diff)
        except PatchReconstructionError as exc:
            raise ApiError(409, "stale_proposal", str(exc)) from exc
        return Change(prop.kind, diff, list(prop.files), prop.breaking)
    if codemod.get("type") != "secret_env":
        raise ApiError(409, "unsupported_codemod", "Unknown codemod recipe")
    rebuilt = secret_fix(ws, str(codemod["file"]), int(codemod["line"]))
    if rebuilt is None or redact(rebuilt.diff) != prop.diff:
        raise ApiError(409, "stale_proposal", "The file changed since this fix was proposed; re-scan the project")
    return Change(rebuilt.kind, rebuilt.diff, rebuilt.files, rebuilt.breaking)


def approve(db: Session, c: Container, finding: Finding, prop: RemediationProposal, actor: Principal,
            comment: str, ip: str | None) -> RemediationProposal:
    if prop.status not in ("validated", "declined", "rejected_by_policy"):
        audit(db, actor.name, "remediation.approve", "proposal", prop.id, "denied",
              {"reason": f"status={prop.status}"}, ip)
        raise ApiError(409, "invalid_state", f"Proposal is '{prop.status}' and cannot be approved")
    ws = scan_workspace(c, prop)
    validation = PolicyEngine(ws).validate(effective_change(prop, ws))
    if (prop.validation or {}).get("codemod"):
        validation["codemod"] = prop.validation["codemod"]
    prop.validation = validation
    if not validation["passed"]:
        prop.status = "rejected_by_policy"
        audit(db, actor.name, "remediation.approve", "proposal", prop.id, "denied",
              {"reason": "guardrail re-validation failed"}, ip)
        db.commit()
        raise ApiError(422, "policy_violation", "Guardrails rejected this change on re-validation",
                       [ch for ch in validation["checks"] if not ch["passed"]])
    prop.status = "approved"
    db.add(Approval(finding_id=finding.id, proposal_id=prop.id, decision="approve", actor=actor.name, comment=comment))
    if finding.status == "open":
        finding.status = "accepted"
    audit(db, actor.name, "remediation.approve", "proposal", prop.id, "allowed",
          {"finding": finding.id, "breaking": prop.breaking}, ip)
    db.commit()
    return prop


def start_apply(db: Session, c: Container, finding: Finding, prop: RemediationProposal, actor: Principal,
                ip: str | None, open_pr: bool = False) -> RemediationProposal:
    if prop.status != "approved":
        audit(db, actor.name, "remediation.apply", "proposal", prop.id, "denied", {"reason": f"status={prop.status}"},
              ip)
        raise ApiError(409, "approval_required", "A human approval is required before a change can be applied")
    if not any(a.proposal_id == prop.id and a.decision == "approve" for a in
               db.query(Approval).filter(Approval.finding_id == finding.id).all()):
        raise ApiError(409, "approval_required", "No approval record found for this proposal")
    prop.status = "applying"
    finding.status = "in_progress"
    audit(db, actor.name, "remediation.apply", "proposal", prop.id, "allowed",
          {"finding": finding.id, "auto_pull_request": open_pr}, ip)
    db.commit()
    prop_id = prop.id
    c.worker.submit_task(lambda: _apply_and_verify(c, prop_id, actor, ip, open_pr))
    return prop


def one_click_fix(db: Session, c: Container, finding: Finding, prop: RemediationProposal, actor: Principal,
                  comment: str, ip: str | None) -> RemediationProposal:
    """Approve → apply on an isolated branch → verify → open a draft PR, from a single explicit human action.

    Every step still runs its normal guardrail: the click is recorded as the approval, policy is re-validated, the
    change is only ever committed to a `skyforge/` branch, and the PR is opened only if verification succeeds.
    """
    if not actor.can("remediation:approve"):
        raise ApiError(403, "forbidden", "Your role cannot approve remediations")
    if prop.status in ("validated", "declined", "rejected_by_policy"):
        approve(db, c, finding, prop, actor, comment or "Approved via one-click fix", ip)
    if prop.status == "approved":
        return start_apply(db, c, finding, prop, actor, ip, open_pr=True)
    if prop.status in publish.PUBLISHABLE:
        publish.open_pull_request(db, c, finding, prop, actor, ip)
        db.refresh(prop)
        return prop
    raise ApiError(409, "invalid_state", f"Proposal is '{prop.status}' and cannot be fixed in one click")


def _apply_and_verify(c: Container, prop_id: str, actor: Principal | str, ip: str | None = None,
                      open_pr: bool = False) -> None:
    name = actor.name if isinstance(actor, Principal) else actor
    try:
        _apply(c, prop_id, name)
        _verify(c, prop_id, name)
        if open_pr and isinstance(actor, Principal):
            _publish(c, prop_id, actor, ip)
    except Exception as exc:  # noqa: BLE001 - record any failure on the proposal; never leave it 'applying'
        log.exception("Remediation %s failed", prop_id)
        with session_scope() as db:
            prop = db.get(RemediationProposal, prop_id)
            if prop:
                prop.status = "verification_failed" if prop.status == "applied" else "apply_failed"
                prop.verification = {**(prop.verification or {}), "error": f"{type(exc).__name__}: {exc}"[:500]}
                if prop.finding and prop.finding.status == "in_progress":
                    prop.finding.status = "accepted"
                audit(db, name, "remediation.error", "proposal", prop_id, "error", {"error": str(exc)[:300]},
                      commit=False)


def _publish(c: Container, prop_id: str, actor: Principal, ip: str | None) -> None:
    """Open the draft PR after a successful verification. A publish failure never fails the fix itself."""
    with session_scope() as db:
        prop = db.get(RemediationProposal, prop_id)
        if prop is None or prop.finding is None:
            return
        if prop.status not in publish.PUBLISHABLE:
            prop.verification = {**(prop.verification or {}),
                                 "pull_request_error": f"Not published: proposal is '{prop.status}'"}
            return
        try:
            publish.open_pull_request(db, c, prop.finding, prop, actor, ip)
        except ApiError as exc:
            log.warning("Auto pull request for %s failed: %s", prop_id, exc.code)
            prop.verification = {**(prop.verification or {}),
                                 "pull_request_error": f"{exc.code}: {exc.message}"[:500]}


def _apply(c: Container, prop_id: str, actor: str) -> None:
    with session_scope() as db:
        prop = db.get(RemediationProposal, prop_id)
        assert prop is not None
        ws = scan_workspace(c, prop)
        change = effective_change(prop, ws)
        validation = PolicyEngine(ws).validate(change)
        if not validation["passed"]:
            prop.status, prop.validation = "rejected_by_policy", validation
            audit(db, actor, "remediation.apply", "proposal", prop_id, "denied", {"reason": "policy"}, commit=False)
            return
        scan = db.get(Scan, prop.scan_id)
        base = scan.commit_sha if scan and scan.commit_sha else run_git(["rev-parse", "HEAD"], cwd=ws.root)
        branch = f"skyforge/fix-{prop.id[-10:]}"
        wt = workspace_dir(c.settings, prop.project_id, prop.scan_id) / "remediation" / prop.id
        if wt.exists():
            try:
                run_git(["worktree", "remove", "--force", str(wt)], cwd=ws.root)
            except RepositoryError:
                pass
        try:
            run_git(["branch", "-D", branch], cwd=ws.root)
        except RepositoryError:
            pass
        run_git(["worktree", "add", "-q", "-b", branch, str(wt), base], cwd=ws.root)
        patch = wt.parent / f"{prop.id}.patch"
        patch.write_text(change.diff if change.diff.endswith("\n") else change.diff + "\n", encoding="utf-8")
        try:
            run_git(["apply", "--whitespace=nowarn", str(patch)], cwd=wt)
        finally:
            patch.unlink(missing_ok=True)
        run_git(["add", "-A"], cwd=wt)
        finding = prop.finding
        msg = (f"SkyForge: {prop.title}\n\nFinding: {finding.id} ({finding.severity})\nAgent: {prop.agent_id}\n"
               f"Approved-by: {', '.join(a.actor for a in db.query(Approval).filter(Approval.proposal_id == prop.id))}\n"
               f"Policy: {validation['policy_version']}")
        run_git(["-c", "user.name=SkyForge Bot", "-c", "user.email=bot@skyforge.local", "commit", "-q", "-m", msg],
                cwd=wt)
        prop.commit_sha = run_git(["rev-parse", "HEAD"], cwd=wt)
        prop.branch, prop.base_commit = branch, base
        prop.status = "applied"
        prop.validation = {**validation, **({"codemod": prop.validation["codemod"]}
                                            if (prop.validation or {}).get("codemod") else {})}
        art_rel = f"{prop.scan_id}/{prop.id}.patch"
        (c.settings.artifacts_dir / art_rel).parent.mkdir(parents=True, exist_ok=True)
        (c.settings.artifacts_dir / art_rel).write_text(prop.diff, encoding="utf-8")
        db.add(ScanArtifact(scan_id=prop.scan_id, project_id=prop.project_id, agent_id=prop.agent_id, kind="patch",
                            name=f"{prop.id}.patch", rel_path=art_rel, media_type="text/x-diff",
                            size=len(prop.diff.encode())))
        prop.verification = {"status": "running", "rollback": f"git worktree remove {wt.name} && git branch -D {branch}",
                             "worktree": str(wt.relative_to(c.settings.data_dir))}
        finding.status = "fixed"
        audit(db, actor, "remediation.applied", "proposal", prop_id, "allowed",
              {"branch": branch, "commit": prop.commit_sha}, commit=False)


def _verify(c: Container, prop_id: str, actor: str) -> None:
    with session_scope() as db:
        prop = db.get(RemediationProposal, prop_id)
        if prop is None or prop.status != "applied":
            return
        wt = workspace_dir(c.settings, prop.project_id, prop.scan_id) / "remediation" / prop.id
        ws = RepoWorkspace(wt)
        finding = prop.finding
        checks: list[dict[str, Any]] = []
        verified: bool | None
        if prop.kind == "dependency_upgrade":
            verified = _verify_dependency(c, ws, finding, checks)
        elif prop.kind in ("test_addition", "functional_test"):
            verified = _verify_tests(c, db, ws, prop, checks)
        elif prop.kind == "refactor":
            verified = _verify_refactor(ws, prop, checks)
        elif prop.kind == "config_fix":
            verified = _verify_config(ws, prop, finding, checks)
        elif prop.kind == "iac_change":
            verified = _verify_iac(ws, prop, checks)
        else:
            verified = None
        if verified is None:
            status = "applied"
            summary = "Applied; automated verification not available for this change type"
        else:
            status = "verified" if verified else "verification_failed"
            summary = "All verification checks passed" if verified else "Verification checks failed"
        prop.status = status
        prop.verification = {**(prop.verification or {}), "status": status, "checks": checks, "summary": summary,
                             "verified_at": utcnow().isoformat()}
        if verified:
            finding.status = "verified"
        elif verified is False:
            finding.status = "in_progress"
        audit(db, actor, "remediation.verify", "proposal", prop_id, "info", {"result": status}, commit=False)


def _verify_dependency(c: Container, ws: RepoWorkspace, finding: Finding, checks: list[dict]) -> bool:
    ev = finding.evidence or {}
    pkg, eco = ev.get("package"), ev.get("ecosystem")
    dep = next((d for d in discover_dependencies(ws) if d.name.lower() == str(pkg).lower() and d.file == finding.target),
               None)
    checks.append({"name": "manifest_parses", "passed": dep is not None,
                   "detail": f"{pkg} {dep.version if dep else 'not found'}"})
    if not dep:
        return False
    advisories = c.osv.query(dep.name, cast(str, eco), dep.version)
    old_ids = {a["id"] for a in ev.get("advisories", [])} | {al for a in ev.get("advisories", []) for al in
                                                              a.get("aliases", [])}
    remaining = [a.id for a in advisories if a.id in old_ids or set(a.aliases) & old_ids]
    checks.append({"name": "osv_rescan", "passed": not remaining,
                   "detail": f"{len(advisories)} advisories for {dep.version}; original remaining: {remaining[:5]}"})
    checks.append({"name": "no_new_advisories", "passed": not advisories,
                   "detail": "clean" if not advisories else f"{len(advisories)} other advisories still apply"})
    return not remaining


def _verify_tests(c: Container, db: Session, ws: RepoWorkspace, prop: RemediationProposal, checks: list[dict]) -> bool | None:
    py = [f for f in prop.files if f.endswith(".py")]
    if not py:
        checks.append({"name": "execution", "passed": False, "detail": "Non-Python suites are not executed"})
        return None
    if not c.sandbox.available():
        checks.append({"name": "sandbox", "passed": False, "detail": "Docker sandbox unavailable — not executed"})
        return None
    res = c.sandbox.run_python_tests(ws.root, test_paths=py, coverage=True)
    db.add(TestRun(scan_id=prop.scan_id, project_id=prop.project_id, agent_id=prop.agent_id, kind="verification",
                   framework="pytest", status=res.status if res.status in ("passed", "failed", "error") else "error",
                   total=res.total, passed=res.passed, failed=res.failed, errors=res.errors, skipped=res.skipped,
                   coverage_after=res.coverage_percent, duration_s=res.duration_s,
                   details={"label": f"Verification of {prop.id}", "failures": res.failures[:10],
                            "reason": res.reason}))
    checks.append({"name": "tests_pass_in_sandbox", "passed": res.status == "passed",
                   "detail": f"{res.passed}/{res.total} passed; coverage {res.coverage_percent}%",
                   "coverage_after": res.coverage_percent})
    return res.status == "passed"


def _verify_refactor(ws: RepoWorkspace, prop: RemediationProposal, checks: list[dict]) -> bool:
    ok = True
    py_files = [f for f in prop.files if f.endswith(".py")]
    js_files = [f for f in prop.files if Path(f).suffix in JS_EXTS]
    for f in py_files:
        try:
            ast.parse(ws.read_text(f))
            checks.append({"name": f"syntax:{f}", "passed": True, "detail": "parses"})
        except SyntaxError as exc:
            ok = False
            checks.append({"name": f"syntax:{f}", "passed": False, "detail": str(exc)})
    if js_files:
        if not prop.base_commit:
            checks.append({"name": "js_refactor_replayed", "passed": False,
                           "detail": "Original commit is missing; cannot verify this refactor"})
            return False
        before = {f: run_git(["show", f"{prop.base_commit}:{f}"], cwd=ws.root, preserve_output=True) for f in js_files}
        after = {f: ws.read_text(f) for f in js_files}
        replayed = verify_js_refactor(before, after)
        checks.append({"name": "js_refactor_replayed", "passed": replayed,
                       "detail": "Replayed supported codemods against the original commit" if replayed
                       else "Change does not match a supported JavaScript refactor"})
        ok = ok and replayed
    exe = ruff_binary()
    if exe and py_files:
        r = subprocess.run([exe, "check", "--isolated", "--no-cache", "--select", RUFF_SAFE_FIX_RULES,
                            "--output-format", "json", "--exit-zero", "--", *py_files], cwd=ws.root,
                           capture_output=True, text=True, timeout=120, check=False)
        remaining = [v for v in json.loads(r.stdout or "[]") if v.get("fix")]
        checks.append({"name": "safe_fixes_applied", "passed": not remaining,
                       "detail": f"{len(remaining)} safe-fixable issues remain"})
        ok = ok and not remaining
    return ok


def _verify_config(ws: RepoWorkspace, prop: RemediationProposal, finding: Finding, checks: list[dict]) -> bool:
    rule = finding.rule_id.split(":", 1)[-1]
    target = finding.target
    text = ws.read_text(target)
    line = (finding.location or {}).get("line", 0)
    lines = text.splitlines()
    # Codemods may insert imports above the offending line, so verify the rewritten lines from the patch itself
    # rather than the recorded line number, which the insertion shifts.
    added = [ln[1:] for ln in (prop.diff or "").splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    removed = [ln[1:] for ln in (prop.diff or "").splitlines() if ln.startswith("-") and not ln.startswith("---")]
    if finding.category == "secret":
        still = scan_secrets("\n".join(added)) if added else [h for h in scan_secrets(text) if h[1] == line]
        checks.append({"name": "secret_removed", "passed": not still,
                       "detail": "rescanned the rewritten lines" if added else "rescanned file"})
        checks.append({"name": "rotation_required", "passed": True,
                       "detail": "Rotate the exposed credential — history still contains it"})
        return not still
    rules = [r for r in CODE_RULES if r.id == rule]
    if rules and added:
        pattern_still = any(rules[0].pattern.search(a) for a in added)
        detail = f"rule {rule} not present in {len(added)} rewritten line(s)"
    else:
        pattern_still = bool(rules and 0 < line <= len(lines) and rules[0].pattern.search(lines[line - 1]))
        detail = f"rule {rule} at line {line}"
    checks.append({"name": "pattern_removed", "passed": not pattern_still, "detail": detail})
    stale = [r for r in removed if r.strip() and r in lines]
    checks.append({"name": "original_line_replaced", "passed": not stale,
                   "detail": "offending line no longer in the file" if not stale else f"{len(stale)} line(s) unchanged"})
    return not pattern_still and not stale



def _baseline_syntax_ok(ws: RepoWorkspace, prop: RemediationProposal, rel: str) -> bool:
    """Was the file already failing its syntax check before the fix branch touched it?"""
    if not prop.base_commit:
        return True
    try:
        original = run_git(["show", f"{prop.base_commit}:{rel}"], cwd=ws.root, timeout=30, preserve_output=True)
    except RepositoryError:
        return True
    with tempfile.TemporaryDirectory(prefix="skyforge-verify-") as tmp:
        probe = Path(tmp) / Path(rel).name
        probe.write_text(original, encoding="utf-8")
        return syntax_check(probe)[0]


def _verify_iac(ws: RepoWorkspace, prop: RemediationProposal, checks: list[dict]) -> bool:
    ok = True
    for f in prop.files:
        valid, msg = syntax_check(ws.path(f))
        if not valid and not _baseline_syntax_ok(ws, prop, f):
            valid, msg = True, f"pre-existing syntax errors, not introduced by this fix ({msg})"
        checks.append({"name": f"terraform_syntax:{f}", "passed": valid, "detail": msg})
        ok = ok and valid
    added = [ln[1:] for ln in prop.diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    content = "\n".join(ws.read_text(f) for f in prop.files)
    present = all(a.strip() in content for a in added if a.strip())
    checks.append({"name": "change_present", "passed": present, "detail": "expected lines found in branch"})
    tf = parse_terraform(ws)
    checks.append({"name": "terraform_resources_parse", "passed": bool(tf), "detail": f"{len(tf)} resources"})
    if shutil.which("terraform"):
        r = subprocess.run(["terraform", "fmt", "-check", "-diff", "-recursive"], cwd=ws.root, capture_output=True,
                           text=True, timeout=60, check=False)
        checks.append({"name": "terraform_fmt", "passed": True,
                       "detail": "formatted" if r.returncode == 0 else "style differences (non-blocking)"})
    return ok and present and bool(tf)



def record_review(db: Session, finding: Finding, decision: str, actor: Principal, comment: str,
                  ip: str | None) -> None:
    mapping = {"accept": "accepted", "dismiss": "dismissed", "reopen": "open", "in_progress": "in_progress"}
    if decision not in mapping:
        raise ApiError(400, "invalid_decision", decision)
    finding.status = mapping[decision]
    db.add(Approval(finding_id=finding.id, decision=decision, actor=actor.name, comment=comment))
    audit(db, actor.name, f"finding.{decision}", "finding", finding.id, "allowed", {"comment": comment[:200]}, ip)
    db.commit()


def decline(db: Session, finding: Finding, prop: RemediationProposal, actor: Principal, comment: str,
            ip: str | None) -> None:
    if prop.status not in ("validated", "approved", "rejected_by_policy", "proposed"):
        raise ApiError(409, "invalid_state", f"Cannot decline a proposal in state '{prop.status}'")
    prop.status = "declined"
    db.add(Approval(finding_id=finding.id, proposal_id=prop.id, decision="decline", actor=actor.name, comment=comment))
    audit(db, actor.name, "remediation.decline", "proposal", prop.id, "allowed", {}, ip)
    db.commit()
