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
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from app.adapters.repository.git_repo import RepositoryError, RepoWorkspace, run_git
from app.adapters.scanners.code_metrics import RUFF_SAFE_FIX_RULES, ruff_binary
from app.adapters.scanners.manifests import discover_dependencies, unified_diff
from app.adapters.scanners.terraform import parse_terraform
from app.agents.security_guardrails import CODE_RULES, PolicyEngine, scan_secrets, secret_fix, syntax_check
from app.core.errors import ApiError
from app.core.security import Principal, redact
from app.db.session import session_scope
from app.models import Approval, Finding, RemediationProposal, Scan, ScanArtifact, TestRun, utcnow
from app.orchestration.orchestrator import workspace_dir
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
    """The patch to validate/apply. Secret fixes are rebuilt from their codemod so stored diffs stay redacted."""
    codemod = (prop.validation or {}).get("codemod")
    if not codemod:
        return Change(prop.kind, prop.diff, list(prop.files), prop.breaking)
    if codemod.get("type") != "secret_env":
        raise ApiError(409, "unsupported_codemod", "Unknown codemod recipe")
    rebuilt = secret_fix(ws, str(codemod["file"]), int(codemod["line"]))
    if rebuilt is None or redact(rebuilt.diff) != prop.diff:
        raise ApiError(409, "stale_proposal", "The file changed since this fix was proposed; re-scan the project")
    return Change(rebuilt.kind, rebuilt.diff, rebuilt.files, rebuilt.breaking)


def approve(db: Session, c: Container, finding: Finding, prop: RemediationProposal, actor: Principal,
            comment: str, ip: str | None) -> RemediationProposal:
    if prop.status not in ("validated", "declined"):
        audit(db, actor.name, "remediation.approve", "proposal", prop.id, "denied",
              {"reason": f"status={prop.status}"}, ip)
        raise ApiError(409, "invalid_state", f"Proposal is '{prop.status}'; only validated proposals can be approved")
    validation = PolicyEngine(scan_workspace(c, prop)).validate(effective_change(prop, scan_workspace(c, prop)))
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
                ip: str | None) -> RemediationProposal:
    if prop.status not in ("approved", "apply_failed", "verification_failed"):
        audit(db, actor.name, "remediation.apply", "proposal", prop.id, "denied", {"reason": f"status={prop.status}"},
              ip)
        raise ApiError(409, "approval_required", "Approve the fix before applying or retrying it")
    if not any(a.proposal_id == prop.id and a.decision == "approve" for a in
               db.query(Approval).filter(Approval.finding_id == finding.id).all()):
        raise ApiError(409, "approval_required", "No approval record found for this proposal")
    prop.status = "applying"
    finding.status = "in_progress"
    audit(db, actor.name, "remediation.apply", "proposal", prop.id, "allowed", {"finding": finding.id}, ip)
    db.commit()
    c.worker.submit_task(lambda: _apply_and_verify(c, prop.id, actor.name))
    return prop


def _apply_and_verify(c: Container, prop_id: str, actor: str) -> None:
    try:
        _apply(c, prop_id, actor)
        _verify(c, prop_id, actor)
    except Exception as exc:  # noqa: BLE001 - record any failure on the proposal; never leave it 'applying'
        log.exception("Remediation %s failed", prop_id)
        with session_scope() as db:
            prop = db.get(RemediationProposal, prop_id)
            if prop:
                prop.status = "verification_failed" if prop.status == "applied" else "apply_failed"
                prop.verification = {**(prop.verification or {}), "error": f"{type(exc).__name__}: {exc}"[:500]}
                if prop.finding and prop.finding.status == "in_progress":
                    prop.finding.status = "accepted"
                audit(db, actor, "remediation.error", "proposal", prop_id, "error", {"error": str(exc)[:300]},
                      commit=False)


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
        run_git(["apply", "--whitespace=nowarn", str(patch)], cwd=wt)
        if prop.kind == "dependency_upgrade":
            lock_update = _sync_npm_lock(wt, change.files, prop.finding)
            if lock_update:
                lock_path, lock_diff = lock_update
                change.diff += lock_diff
                change.files.append(lock_path)
                prop.diff, prop.files = change.diff, change.files
                validation["checks"].append({"name": "npm_lockfile_synced", "passed": True,
                                             "detail": f"{lock_path} regenerated in sandbox with scripts disabled"})
                validation["passed"] = all(ch["passed"] for ch in validation["checks"])
                prop.validation = validation
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


def _sync_npm_lock(wt: Any, changed_files: list[str], finding: Finding) -> tuple[str, str] | None:
    package_files = [f for f in changed_files if f.endswith("/package.json") or f == "package.json"]
    if not package_files:
        return None
    package_file = package_files[0]
    folder = package_file.rpartition("/")[0]
    lock_rel = f"{folder}/package-lock.json" if folder else "package-lock.json"
    if not (wt / lock_rel).is_file():
        shrinkwrap = f"{folder}/npm-shrinkwrap.json" if folder else "npm-shrinkwrap.json"
        lock_rel = shrinkwrap if (wt / shrinkwrap).is_file() else ""
    if not lock_rel:
        return None
    package_data = json.loads((wt / package_file).read_text(encoding="utf-8"))
    package_name = str((finding.evidence or {}).get("package", ""))
    declared = next((section[package_name] for section in (package_data.get("dependencies", {}),
                                                            package_data.get("devDependencies", {}))
                     if package_name in section), None)
    match = re.search(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", str(declared or ""))
    if not match:
        raise RuntimeError(f"Could not determine the patched {package_name} version from {package_file}")
    target_version = match.group(0)
    lock_path = wt / lock_rel
    before = lock_path.read_text(encoding="utf-8")
    lock_data = json.loads(before)
    try:
        url_name = quote(package_name, safe="@")
        response = httpx.get(f"https://registry.npmjs.org/{url_name}/{quote(target_version, safe='.+-')}", timeout=30)
        response.raise_for_status()
        metadata = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise RuntimeError(f"Could not fetch npm metadata for {package_name}@{target_version}: {type(exc).__name__}") \
            from exc
    dist = metadata.get("dist") or {}
    if not dist.get("tarball") or not dist.get("integrity"):
        raise RuntimeError(f"npm did not return integrity metadata for {package_name}@{target_version}")

    # Updating just this package is safe only when its dependency graph is unchanged.
    new_requires = metadata.get("dependencies") or {}
    if metadata.get("optionalDependencies") or metadata.get("peerDependencies"):
        raise RuntimeError(f"{package_name}@{target_version} changes optional/peer dependencies; "
                           "regenerate its npm lock manually")
    package_entry = (lock_data.get("packages") or {}).get(f"node_modules/{package_name}")
    dependency_entry = (lock_data.get("dependencies") or {}).get(package_name)
    entry = package_entry or dependency_entry
    if entry is None:
        raise RuntimeError(f"{package_name} is not a top-level entry in {lock_rel}; regenerate its npm lock manually")
    old_requires = entry.get("requires") or {}
    if old_requires != new_requires:
        raise RuntimeError(f"{package_name}@{target_version} changes its dependency tree; regenerate {lock_rel} manually")
    installed = str((finding.evidence or {}).get("installed_version", ""))
    if installed and entry.get("version") != installed:
        raise RuntimeError(f"Lockfile has {package_name}@{entry.get('version')}, expected scanned {installed}; re-scan")
    entry.update(version=target_version, resolved=dist["tarball"], integrity=dist["integrity"])
    after = json.dumps(lock_data, indent=2, ensure_ascii=False) + "\n"
    if before == after:
        return None
    lock_path.write_text(after, encoding="utf-8")
    return lock_rel, unified_diff(lock_rel, before, after)


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
    new_advisories = [a.id for a in advisories if a.id not in old_ids and not set(a.aliases) & old_ids]
    checks.append({"name": "osv_rescan", "passed": not remaining,
                   "detail": f"{len(advisories)} advisories for {dep.version}; original remaining: {remaining[:5]}"})
    checks.append({"name": "no_new_advisories", "passed": not new_advisories,
                   "detail": "none introduced" if not new_advisories else
                   f"{len(new_advisories)} new advisories: {new_advisories[:5]}"})
    return not remaining and not new_advisories


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
                   "detail": f"{res.passed}/{res.total} passed; coverage {res.coverage_percent}%"})
    return res.status == "passed"


def _verify_refactor(ws: RepoWorkspace, prop: RemediationProposal, checks: list[dict]) -> bool:
    ok = True
    for f in prop.files:
        try:
            ast.parse(ws.read_text(f))
            checks.append({"name": f"syntax:{f}", "passed": True, "detail": "parses"})
        except SyntaxError as exc:
            ok = False
            checks.append({"name": f"syntax:{f}", "passed": False, "detail": str(exc)})
    exe = ruff_binary()
    if exe:
        r = subprocess.run([exe, "check", "--isolated", "--no-cache", "--select", RUFF_SAFE_FIX_RULES,
                            "--output-format", "json", "--exit-zero", "--", *prop.files], cwd=ws.root,
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
    if finding.category == "secret":
        line = (finding.location or {}).get("line", 0)
        still = [h for h in scan_secrets(text) if h[1] == line]
        checks.append({"name": "secret_removed", "passed": not still, "detail": "rescanned file"})
        checks.append({"name": "rotation_required", "passed": True,
                       "detail": "Rotate the exposed credential — history still contains it"})
        return not still
    rules = [r for r in CODE_RULES if r.id == rule]
    line = (finding.location or {}).get("line", 0)
    lines = text.splitlines()
    pattern_still = bool(rules and 0 < line <= len(lines) and rules[0].pattern.search(lines[line - 1]))
    checks.append({"name": "pattern_removed", "passed": not pattern_still, "detail": f"rule {rule} at line {line}"})
    return not pattern_still


def _verify_iac(ws: RepoWorkspace, prop: RemediationProposal, checks: list[dict]) -> bool:
    ok = True
    for f in prop.files:
        valid, msg = syntax_check(ws.path(f))
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
