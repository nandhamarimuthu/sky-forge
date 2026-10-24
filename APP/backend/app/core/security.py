"""Authentication principals, secret redaction and filesystem path safety."""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import Settings

log = logging.getLogger(__name__)

ROLES = ("viewer", "engineer", "admin")
DEV_FALLBACK_TOKEN = "skyforge-dev-token"  # noqa: S105 - dev-only; refused when APP_ENV=prod

PERMISSIONS: dict[str, set[str]] = {
    "viewer": {"read"},
    "engineer": {"read", "project:create", "scan:run", "scan:cancel", "finding:review", "remediation:approve",
                 "remediation:apply"},
    "admin": {"read", "project:create", "project:delete", "scan:run", "scan:cancel", "finding:review",
              "remediation:approve", "remediation:apply", "settings:write", "audit:read"},
}


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    projects: frozenset[str] = field(default_factory=lambda: frozenset({"*"}))

    def can(self, permission: str) -> bool:
        return permission in PERMISSIONS.get(self.role, set())

    def can_access_project(self, project_id: str, project_name: str | None = None) -> bool:
        return "*" in self.projects or project_id in self.projects or (project_name or "") in self.projects


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


class TokenRegistry:
    """Holds only SHA-256 digests of API tokens; compares in constant time."""

    def __init__(self, settings: Settings):
        self._entries: list[tuple[bytes, Principal]] = []
        raw = settings.api_tokens.strip()
        if not raw:
            if settings.app_env == "prod":
                raise RuntimeError("API_TOKENS must be configured in production")
            log.warning("API_TOKENS not set — using development token. Never use this outside local dev.")
            raw = f"developer:admin:{DEV_FALLBACK_TOKEN}"
        for entry in raw.split(","):
            parts = entry.strip().split(":")
            if len(parts) < 3:
                raise RuntimeError("Invalid API_TOKENS entry; expected name:role:token[:projects]")
            name, role, token = parts[0], parts[1], parts[2]
            if role not in ROLES:
                raise RuntimeError(f"Unknown role '{role}' in API_TOKENS")
            if len(token) < 12:
                raise RuntimeError("API tokens must be at least 12 characters")
            if settings.app_env == "prod" and ("change-me" in token or token == DEV_FALLBACK_TOKEN):
                raise RuntimeError("Refusing to start in prod with a placeholder token")
            projects = frozenset(p for p in (parts[3].split("|") if len(parts) > 3 else ["*"]) if p)
            self._entries.append((_digest(token), Principal(name=name, role=role, projects=projects)))

    def resolve(self, token: str | None) -> Principal | None:
        if not token:
            return None
        d = _digest(token)
        found: Principal | None = None
        for digest, principal in self._entries:
            if hmac.compare_digest(digest, d):
                found = principal
        return found


# ---------- Redaction ----------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe_key", re.compile(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("generic_secret_assignment", re.compile(
        r"(?i)[A-Za-z0-9_]*(password|passwd|secret|api_?key|access_?token|auth_?token|client_?secret)[A-Za-z0-9_]*"
        r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
    ("url_credentials", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@[^\s]+")),
]

_BEARER = re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s'\"]+")


def redact(text: str) -> str:
    if not text:
        return text
    out = _BEARER.sub(r"\1[REDACTED]", text)
    for _, pattern in SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        record.msg = redact(msg)
        record.args = ()
        return True


# ---------- Path safety ----------

class PathEscapeError(ValueError):
    pass


def safe_join(root: Path, relative: str) -> Path:
    """Resolve `relative` under `root`, rejecting traversal, absolute paths and symlink escapes."""
    if not relative or relative.startswith(("/", "\\")) or "\x00" in relative:
        raise PathEscapeError(f"Illegal path: {relative!r}")
    root_resolved = root.resolve()
    candidate = (root_resolved / relative).resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise PathEscapeError(f"Path escapes workspace: {relative!r}")
    return candidate


def is_within(root: Path, path: Path) -> bool:
    try:
        r, p = root.resolve(), path.resolve()
    except OSError:
        return False
    return p == r or r in p.parents
