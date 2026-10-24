"""Publish a verified fix: push its isolated branch to GitHub and open a draft pull request.

Only ever triggered by an explicit human action after approval + verification. Never force-pushes, never writes
to the default branch, and the credential is resolved at call time (never stored, logged or put on a command line).
Auth order: a per-project token secret ref → a configured GitHub App (short-lived installation token) → GITHUB_TOKEN.
- Repo the credential can push to → branch + PR in that repo.
- Public repo without push access → fork into the token owner's account, PR inside the fork (upstream maintainers
  are never contacted automatically). PAT only — installation tokens cannot fork.
- Bundled sample (fixture) repo → private `skyforge-<name>` repo in the token owner's account. PAT only.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.adapters.repository.git_repo import RepositoryError, run_git
from app.core.config import secret_from_env
from app.core.errors import ApiError
from app.core.security import Principal, redact
from app.models import Approval, Finding, Project, RemediationProposal
from app.orchestration.orchestrator import workspace_dir
from app.services.audit import audit
from app.services.container import Container
from app.services.github_app import app_configured, can_push, installation_auth

PUBLISHABLE = ("verified", "applied")


class _GitHub:
    def __init__(self, api: str, token: str):
        self.client = httpx.Client(base_url=api, timeout=30, follow_redirects=False, headers={
            "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SkyForge-AI"})

    def call(self, method: str, path: str, ok: tuple[int, ...] = (200, 201, 202), **kw: Any) -> httpx.Response:
        try:
            r = self.client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise ApiError(502, "github_unreachable", f"GitHub API request failed: {type(exc).__name__}") from exc
        if r.status_code == 401:
            raise ApiError(422, "github_auth", "GitHub rejected the token (401) — check the token and its scopes")
        if r.status_code not in ok:
            msg = r.json().get("message", "") if r.headers.get("content-type", "").startswith("application/json") else ""
            raise ApiError(502, "github_error", f"GitHub {method} {path.split('?')[0]} → {r.status_code} {msg}"[:300])
        return r

    def wait_for_repo(self, full: str, tries: int = 15) -> dict[str, Any]:
        for _ in range(tries):
            r = self.call("GET", f"/repos/{full}", ok=(200, 404))
            if r.status_code == 200:
                return r.json()
            time.sleep(2)
        raise ApiError(504, "github_timeout", f"Repository {full} did not become available")


def _token(c: Container, project: Project) -> tuple[str, str | None]:
    """Returns (token, app installation login). A per-repo PAT ref wins; otherwise the GitHub App; otherwise the PAT."""
    ref = project.repository.token_secret_ref if project.repository else None
    token = secret_from_env(ref)
    if token:
        return token, None
    if app_configured(c.settings):
        return installation_auth(c.settings)
    token = secret_from_env(c.settings.github_token_env)
    if not token:
        raise ApiError(422, "github_token_missing",
                       f"Configure a GitHub App (GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, "
                       f"GITHUB_APP_PRIVATE_KEY_PATH) or set {ref or c.settings.github_token_env} to a GitHub token "
                       "with repo + pull request write access to enable pushing branches and opening PRs")
    return token, None


def publish_enabled(c: Container) -> bool:
    return bool(secret_from_env(c.settings.github_token_env)) or app_configured(c.settings)


def github_auth_mode(c: Container) -> str:
    """Which credential the publish flow will use: the GitHub App, a PAT, or nothing."""
    if app_configured(c.settings):
        return "app"
    return "pat" if secret_from_env(c.settings.github_token_env) else "none"



def _coverage_section(finding: Finding, prop: RemediationProposal) -> list[str]:
    """Extra PR context for coverage work: what the tests cover and how coverage moved."""
    ev = finding.evidence or {}
    before = ev.get("coverage_percent")
    after = next((ch.get("coverage_after") for ch in (prop.verification or {}).get("checks", [])
                  if ch.get("coverage_after") is not None), None)
    lines = ["", "#### Test coverage"]
    if before is not None:
        lines.append(f"- `{finding.target}` line coverage before: **{before:.0f}%**")
    if after is not None:
        lines.append(f"- Measured in the SkyForge sandbox after these tests: **{after:.0f}%**")
    targets = ev.get("coverage_targets") or []
    if targets:
        lines.append("- Previously uncovered code these tests exercise:")
        lines += [f"  - `{t.get('function')}` (line {t.get('line')}, complexity {t.get('complexity')}) — "
                  f"lines {t.get('missing_line_ranges') or '?'}" for t in targets[:8]]
    lines.append(f"- Files added/changed: {', '.join(f'`{f}`' for f in list(prop.files)[:20]) or 'n/a'}")
    return lines


def _body(finding: Finding, prop: RemediationProposal, approvers: list[str]) -> str:
    checks = (prop.verification or {}).get("checks", [])
    lines = [f"### {prop.title}", "", f"**Finding:** `{finding.id}` · {finding.severity} · `{finding.rule_id}`",
             f"**Target:** `{finding.target}`", "", finding.description[:1500], "",
             f"**Recommendation:** {finding.recommendation[:800]}"]
    if finding.category == "coverage" or prop.kind in ("test_addition", "functional_test"):
        lines += _coverage_section(finding, prop)
    lines += ["", "#### Verification"]
    lines += [f"- {'✅' if ch.get('passed') else '❌'} {ch.get('name')}: {str(ch.get('detail', ''))[:200]}"
              for ch in checks] or ["- (no automated verification for this change type)"]
    lines += ["", f"Approved in SkyForge by: {', '.join(approvers) or 'n/a'}",
              f"Guardrail policy: {(prop.validation or {}).get('policy_version', 'n/a')}", "",
              "_Opened by SkyForge AI as a draft. Review, run your CI and merge manually._"]
    return redact("\n".join(lines))[:60000]


def open_pull_request(db: Session, c: Container, finding: Finding, prop: RemediationProposal, actor: Principal,
                      ip: str | None) -> dict[str, Any]:
    existing = (prop.verification or {}).get("pull_request")
    if existing and existing.get("url"):
        return dict(existing)
    if prop.status not in PUBLISHABLE or not prop.branch or not prop.commit_sha:
        audit(db, actor.name, "remediation.publish", "proposal", prop.id, "denied", {"reason": f"status={prop.status}"},
              ip)
        raise ApiError(409, "not_verified", "Only applied/verified fixes on an isolated branch can be pushed")
    approvers = [a.actor for a in db.query(Approval).filter(Approval.proposal_id == prop.id,
                                                            Approval.decision == "approve")]
    if not approvers:
        raise ApiError(409, "approval_required", "No approval record found for this proposal")
    if not prop.branch.startswith("skyforge/"):
        raise ApiError(409, "invalid_branch", "Refusing to push a branch outside the skyforge/ namespace")
    project = db.get(Project, prop.project_id)
    repo = project.repository if project else None
    if project is None or repo is None or repo.provider not in ("github", "local-fixture"):
        raise ApiError(422, "unsupported_provider", "Pull requests are supported for GitHub repositories")
    wt = workspace_dir(c.settings, prop.project_id, prop.scan_id) / "remediation" / prop.id
    if not (wt / ".git").exists():
        raise ApiError(409, "workspace_missing", "The fix branch workspace no longer exists; re-apply the fix")

    token, app_login = _token(c, project)
    gh = _GitHub(c.settings.github_api_url, token)
    login = app_login or gh.call("GET", "/user").json()["login"]
    mode: str
    if repo.provider == "local-fixture":
        if app_login:
            raise ApiError(422, "github_app_unsupported_flow",
                           "GitHub App installation tokens cannot create repositories. Set a GITHUB_TOKEN (PAT) to "
                           "publish bundled sample repositories, or scan a real repository the app is installed on")
        target = f"{login}/skyforge-{repo.name}"
        r = gh.call("GET", f"/repos/{target}", ok=(200, 404))
        if r.status_code == 404:
            gh.call("POST", "/user/repos", json={"name": f"skyforge-{repo.name}", "private": True, "auto_init": False,
                                                 "description": f"SkyForge AI demo copy of sample repo {repo.name}"})
            gh.wait_for_repo(target)
        base = f"skyforge/base-{prop.scan_id[-10:]}"
        mode = "sample-repo"
    else:
        r = gh.call("GET", f"/repos/{repo.owner}/{repo.name}", ok=(200, 404))
        if r.status_code == 404 and app_login:
            raise ApiError(422, "github_app_no_access",
                           f"The GitHub App installation cannot see {repo.owner}/{repo.name}. Install the app on that "
                           "repository (Contents: write, Pull requests: write), or set a GITHUB_TOKEN (PAT)")
        if r.status_code == 404:
            raise ApiError(422, "github_repo_not_found", f"{repo.owner}/{repo.name} is not visible to this token")
        upstream = r.json()
        # Installation tokens always report all-false repo permissions, so trust the installation grants instead.
        pushable = can_push(c.settings) if app_login else bool((upstream.get("permissions") or {}).get("push"))
        if pushable:
            target, base, mode = f"{repo.owner}/{repo.name}", repo.branch or upstream["default_branch"], "direct"
        else:
            if app_login:
                raise ApiError(422, "github_app_no_access",
                               "The GitHub App installation lacks Contents: write and Pull requests: write. Grant "
                               "those permissions (and accept them on the installation), or set a GITHUB_TOKEN (PAT)")
            fork = gh.call("POST", f"/repos/{repo.owner}/{repo.name}/forks", json={}).json()
            target = fork["full_name"]
            base = gh.wait_for_repo(target)["default_branch"]
            mode = "fork"

    url = f"https://github.com/{target}.git"
    refspecs = [f"{prop.commit_sha}:refs/heads/{prop.branch}"]
    if mode == "sample-repo":
        refspecs.insert(0, f"{prop.base_commit}:refs/heads/{base}")
    try:
        run_git(["push", "--no-verify", url, *refspecs], cwd=wt, timeout=120, token=token)
    except RepositoryError as exc:
        audit(db, actor.name, "remediation.publish", "proposal", prop.id, "error", {"error": str(exc)[:300]}, ip)
        raise ApiError(502, "push_failed", redact(str(exc))[:400]) from exc

    head = prop.branch
    r = gh.call("POST", f"/repos/{target}/pulls", ok=(201, 422), json={
        "title": f"SkyForge: {prop.title}"[:250], "head": head, "base": base, "draft": True,
        "body": _body(finding, prop, approvers)})
    if r.status_code == 422:
        found = gh.call("GET", f"/repos/{target}/pulls", params={"head": f"{target.split('/')[0]}:{head}",
                                                                 "state": "open"}).json()
        if not found:
            raise ApiError(502, "pr_failed", f"GitHub refused the pull request: {r.json().get('message', '')}"[:300])
        pr = found[0]
    else:
        pr = r.json()
    info = {"url": pr["html_url"], "number": pr["number"], "repo": target, "branch": head, "base": base,
            "mode": mode, "draft": pr.get("draft", True), "opened_by": actor.name}
    prop.verification = {**(prop.verification or {}), "pull_request": info}
    audit(db, actor.name, "remediation.publish", "proposal", prop.id, "allowed",
          {"repo": target, "pr": pr["number"], "mode": mode, "branch": head}, ip)
    db.commit()
    return info
