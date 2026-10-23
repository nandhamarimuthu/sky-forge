"""Publish a verified fix: push its isolated branch to GitHub and open a draft pull request.

Only ever triggered by an explicit human action after approval + verification. Never force-pushes, never writes
to the default branch, and the token is read from the environment (never stored, logged or put on a command line).
- Repo the token can push to → branch + PR in that repo.
- Public repo without push access → fork into the token owner's account, PR inside the fork (upstream maintainers
  are never contacted automatically).
- Bundled sample (fixture) repo → private `skyforge-<name>` repo in the token owner's account.
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


def _token(c: Container, project: Project) -> str:
    ref = (project.repository.token_secret_ref if project.repository else None) or c.settings.github_token_env
    token = secret_from_env(ref)
    if not token:
        raise ApiError(422, "github_token_missing",
                       f"Set {ref} (environment or .env) to a GitHub token with repo + pull request write access "
                       "to enable pushing branches and opening PRs")
    return token


def publish_enabled(c: Container) -> bool:
    return bool(secret_from_env(c.settings.github_token_env))


def _body(finding: Finding, prop: RemediationProposal, approvers: list[str]) -> str:
    checks = (prop.verification or {}).get("checks", [])
    lines = [f"### {prop.title}", "", f"**Finding:** `{finding.id}` · {finding.severity} · `{finding.rule_id}`",
             f"**Target:** `{finding.target}`", "", finding.description[:1500], "",
             f"**Recommendation:** {finding.recommendation[:800]}", "", "#### Verification"]
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

    token = _token(c, project)
    gh = _GitHub(c.settings.github_api_url, token)
    login = gh.call("GET", "/user").json()["login"]
    mode: str
    if repo.provider == "local-fixture":
        target = f"{login}/skyforge-{repo.name}"
        r = gh.call("GET", f"/repos/{target}", ok=(200, 404))
        if r.status_code == 404:
            gh.call("POST", "/user/repos", json={"name": f"skyforge-{repo.name}", "private": True, "auto_init": False,
                                                 "description": f"SkyForge AI demo copy of sample repo {repo.name}"})
            gh.wait_for_repo(target)
        base = f"skyforge/base-{prop.scan_id[-10:]}"
        mode = "sample-repo"
    else:
        upstream = gh.call("GET", f"/repos/{repo.owner}/{repo.name}").json()
        if (upstream.get("permissions") or {}).get("push"):
            target, base, mode = f"{repo.owner}/{repo.name}", repo.branch or upstream["default_branch"], "direct"
        else:
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
