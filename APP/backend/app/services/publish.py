"""Publish a verified fix: push its isolated branch to GitHub and open a draft pull request.

Only ever triggered by an explicit human action after approval + verification. Never force-pushes, never writes
to the default branch, and the token is read from the environment (never stored, logged or put on a command line).
- Repo the token can push to → branch + PR in that repo.
- Public repo without push access → fork into the token owner's account, PR inside the fork (upstream maintainers
  are never contacted automatically).
- Bundled sample (fixture) repo → private `skyforge-<name>` repo in the token owner's account.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any

import httpx
import jwt
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
_APP_TOKEN_LOCK = threading.Lock()
_APP_TOKEN: tuple[str, float, str] | None = None


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


def _token(c: Container, project: Project, prefer_app: bool = True) -> tuple[str, bool]:
    ref = (project.repository.token_secret_ref if project.repository else None) or c.settings.github_token_env
    app_id = c.settings.github_app_id
    installation_id = c.settings.github_app_installation_id
    key_path = c.settings.github_app_private_key_path
    token = secret_from_env(ref)
    if prefer_app and app_id and installation_id and key_path:
        return _installation_token(c.settings.github_api_url, app_id, installation_id, key_path), True
    if not token:
        raise ApiError(422, "github_token_missing",
                       "Configure GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID and "
                       "GITHUB_APP_PRIVATE_KEY_PATH, or set a GitHub token in GITHUB_TOKEN")
    return token, False


def _app_configured(c: Container) -> bool:
    key_path = c.settings.github_app_private_key_path
    return bool(c.settings.github_app_id and c.settings.github_app_installation_id and key_path and key_path.is_file())


def publish_enabled(c: Container) -> bool:
    return _app_configured(c) or bool(secret_from_env(c.settings.github_token_env))


def _installation_token(api: str, app_id: str, installation_id: str, key_path: Any) -> str:
    global _APP_TOKEN
    cache_key = f"{app_id}:{installation_id}:{key_path}"
    now = time.time()
    with _APP_TOKEN_LOCK:
        if _APP_TOKEN and _APP_TOKEN[2] == cache_key and _APP_TOKEN[1] > now + 60:
            return _APP_TOKEN[0]
        try:
            private_key = key_path.read_text(encoding="utf-8")
            app_jwt = jwt.encode({"iss": app_id, "iat": int(now) - 60, "exp": int(now) + 540}, private_key,
                                 algorithm="RS256")
        except (OSError, ValueError, jwt.PyJWTError) as exc:
            raise ApiError(500, "github_app_key_invalid", "Could not read or sign with the configured GitHub App PEM") \
                from exc
        try:
            response = httpx.post(
                f"{api.rstrip('/')}/app/installations/{installation_id}/access_tokens",
                headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SkyForge-AI"}, timeout=30)
        except httpx.HTTPError as exc:
            raise ApiError(502, "github_unreachable", "Could not exchange GitHub App JWT for an installation token") \
                from exc
        if response.status_code not in (200, 201):
            raise ApiError(422, "github_app_installation",
                           f"GitHub App installation token request failed ({response.status_code})")
        try:
            data = response.json()
            token = data["token"]
            expires = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
            expiry = expires.timestamp()
        except (KeyError, TypeError, ValueError) as exc:
            raise ApiError(502, "github_app_response", "GitHub returned an invalid installation-token response") \
                from exc
        _APP_TOKEN = (token, expiry, cache_key)
        return token


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

    if repo.provider == "local-fixture" and _app_configured(c) and not secret_from_env(c.settings.github_token_env):
        raise ApiError(422, "github_app_sample_repo",
                       "A GitHub App installation token cannot create and install itself on a new sample repository. "
                       "Create a private skyforge-<name> repository, install the App on it, and register that repo "
                       "as a project; or configure GITHUB_TOKEN for sample-repo publishing.")
    token, is_app = _token(c, project, prefer_app=repo.provider != "local-fixture")
    gh = _GitHub(c.settings.github_api_url, token)
    mode: str
    if repo.provider == "local-fixture":
        login = gh.call("GET", "/user").json().get("login")
        if not login:
            raise ApiError(502, "github_identity", "GitHub did not return the authenticated account name")
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
        if is_app or (upstream.get("permissions") or {}).get("push"):
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
