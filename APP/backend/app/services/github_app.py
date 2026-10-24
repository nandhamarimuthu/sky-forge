"""GitHub App authentication: mint short-lived installation access tokens.

Preferred over a personal access token — the app signs a 9-minute RS256 JWT with its private key and exchanges it
for an installation token (valid 1 hour) scoped to the repositories the app is installed on. Tokens are cached in
memory until shortly before they expire and are never persisted, logged or passed on a command line.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt

from app.core.config import Settings, secret_from_env
from app.core.errors import ApiError

_JWT_TTL_S = 540
_REFRESH_MARGIN_S = 300


@dataclass
class _Cached:
    token: str
    expires_at: float
    login: str
    permissions: dict[str, str]


_cache: dict[str, _Cached] = {}


def app_configured(settings: Settings) -> bool:
    """True when an app id, installation id and a readable private key are all available."""
    if not settings.github_app_configured:
        return False
    try:
        _private_key(settings)
    except ApiError:
        return False
    return True


def _private_key(settings: Settings) -> str:
    pem = secret_from_env(settings.github_app_private_key_env)
    if pem:
        return pem.replace("\\n", "\n")
    path = settings.github_app_private_key_path
    if path and path.is_file():
        return path.read_text(encoding="utf-8")
    raise ApiError(422, "github_app_key_missing",
                   f"Set {settings.github_app_private_key_env} or GITHUB_APP_PRIVATE_KEY_PATH to the GitHub App "
                   "private key (.pem) to enable pushing branches and opening PRs")


def app_jwt(settings: Settings) -> str:
    now = int(time.time())
    try:
        return jwt.encode({"iat": now - 60, "exp": now + _JWT_TTL_S, "iss": settings.github_app_id},
                          _private_key(settings), algorithm="RS256")
    except ApiError:
        raise
    except Exception as exc:  # invalid/corrupt PEM
        raise ApiError(422, "github_app_key_invalid",
                       f"Could not sign a GitHub App JWT: {type(exc).__name__} — check the private key") from exc


def _call(settings: Settings, method: str, path: str, bearer: str, ok: tuple[int, ...]) -> dict[str, Any]:
    try:
        r = httpx.request(method, f"{settings.github_api_url.rstrip('/')}{path}", timeout=30, headers={
            "Authorization": f"Bearer {bearer}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SkyForge-AI"})
    except httpx.HTTPError as exc:
        raise ApiError(502, "github_unreachable", f"GitHub API request failed: {type(exc).__name__}") from exc
    if r.status_code not in ok:
        msg = r.json().get("message", "") if r.headers.get("content-type", "").startswith("application/json") else ""
        raise ApiError(422, "github_app_auth",
                       f"GitHub App authentication failed ({r.status_code}) on {path}: {msg}"[:300])
    return r.json()


def _expiry_epoch(value: str | None) -> float:
    if not value:
        return time.time() + 3600
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=UTC).timestamp()
    except ValueError:
        return time.time() + 3600


def installation_auth(settings: Settings) -> tuple[str, str]:
    """Returns (installation access token, login of the account the app is installed on)."""
    cached = _refresh(settings)
    return cached.token, cached.login


def can_push(settings: Settings) -> bool:
    """GitHub reports all-false repo `permissions` for installation tokens, so read the installation grants."""
    perms = _refresh(settings).permissions
    return perms.get("contents") == "write" and perms.get("pull_requests") == "write"


def _refresh(settings: Settings) -> _Cached:
    if not settings.github_app_configured:
        raise ApiError(422, "github_app_not_configured",
                       "Set GITHUB_APP_ID and GITHUB_APP_INSTALLATION_ID to use GitHub App authentication")
    key = f"{settings.github_app_id}:{settings.github_app_installation_id}"
    cached = _cache.get(key)
    if cached and cached.expires_at - _REFRESH_MARGIN_S > time.time():
        return cached
    bearer = app_jwt(settings)
    inst_id = settings.github_app_installation_id
    installation = _call(settings, "GET", f"/app/installations/{inst_id}", bearer, (200,))
    login = str((installation.get("account") or {}).get("login") or "")
    perms = {str(k): str(v) for k, v in (installation.get("permissions") or {}).items()}
    data = _call(settings, "POST", f"/app/installations/{inst_id}/access_tokens", bearer, (201,))
    token = str(data.get("token") or "")
    if not token:
        raise ApiError(502, "github_app_token_failed", "GitHub returned no installation access token")
    fresh = _Cached(token=token, expires_at=_expiry_epoch(data.get("expires_at")), login=login, permissions=perms)
    _cache[key] = fresh
    return fresh


def reset_cache() -> None:
    _cache.clear()
