"""Provider-neutral repository adapter: URL validation, sandboxed `git clone`, and safe file access."""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from app.core.security import PathEscapeError, is_within, safe_join

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".tox", ".mypy_cache",
             ".pytest_cache", "vendor", "site-packages", ".next", "coverage", ".sf_deps", ".idea", ".vscode",
             "target", ".terraform", "bower_components"}
LANG_BY_EXT = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
               ".tsx": "typescript", ".go": "go", ".java": "java", ".rb": "ruby", ".tf": "terraform",
               ".kt": "kotlin", ".cs": "csharp", ".php": "php", ".rs": "rust"}
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


class RepositoryError(Exception):
    pass


@dataclass(frozen=True)
class RepoRef:
    provider: str
    url: str
    owner: str
    name: str


def parse_repo_url(raw: str, allowed_hosts: list[str], fixtures_dir: Path) -> RepoRef:
    raw = raw.strip()
    if raw.startswith("fixture:"):
        name = raw.split(":", 1)[1]
        if not _SEGMENT.match(name):
            raise RepositoryError("Invalid fixture name")
        path = safe_join(fixtures_dir / "repos", name)
        if not path.is_dir():
            raise RepositoryError(f"Fixture repository '{name}' not found")
        return RepoRef("local-fixture", f"fixture:{name}", "fixtures", name)

    if not raw.startswith("https://"):
        raise RepositoryError("Only https:// repository URLs are accepted")
    parsed = urlparse(raw)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port:
        raise RepositoryError("Repository URL must not contain credentials, ports, query strings or fragments")
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host not in allowed_hosts:
        raise RepositoryError(f"Host '{host}' is not in the allowed list: {', '.join(allowed_hosts)}")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise RepositoryError("URL must look like https://host/owner/repository")
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[:-4]
    if not (_SEGMENT.match(owner) and _SEGMENT.match(name)):
        raise RepositoryError("Owner or repository name contains illegal characters")
    provider = host.split(".")[0]
    return RepoRef(provider, f"https://{host}/{owner}/{name}", owner, name)


def _git_env(token: str | None = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": "/tmp",  # noqa: S108 - isolate from user git config / credential helpers
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ASKPASS": "/bin/echo",
    }
    if token:
        # Passed via environment-only config so it never appears in process arguments or logs.
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                    "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}"})
    return env


_SAFE_GIT = ["-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "core.symlinks=false",
             "-c", "submodule.recurse=false", "-c", "core.fsmonitor=false"]


def run_git(args: list[str], cwd: Path | None = None, timeout: int = 60, token: str | None = None) -> str:
    try:
        res = subprocess.run(["git", *_SAFE_GIT, *args], cwd=cwd, env=_git_env(token), capture_output=True,
                             text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RepositoryError(f"git {args[0]} timed out after {timeout}s") from exc
    if res.returncode != 0:
        raise RepositoryError(f"git {args[0]} failed: {res.stderr.strip()[-400:]}")
    return res.stdout.strip()


def dir_size_mb(path: Path) -> float:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            fp = Path(root) / f
            if not fp.is_symlink():
                try:
                    total += fp.stat().st_size
                except OSError:
                    pass
    return total / (1024 * 1024)


def materialize(ref: RepoRef, dest: Path, *, branch: str | None, fixtures_dir: Path, timeout: int,
                max_mb: int, token: str | None = None) -> str:
    """Clone (or copy fixture) into dest and return the HEAD commit sha."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if ref.provider == "local-fixture":
        src = safe_join(fixtures_dir / "repos", ref.name)
        shutil.copytree(src, dest, symlinks=False, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        run_git(["init", "-q", "-b", "main"], cwd=dest)
        run_git(["add", "-A"], cwd=dest)
        run_git(["-c", "user.name=SkyForge", "-c", "user.email=bot@skyforge.local", "commit", "-q", "-m",
                 "fixture snapshot"], cwd=dest)
    else:
        args = ["clone", "--depth", "50", "--no-tags", "--single-branch", "--no-recurse-submodules"]
        if branch:
            args += ["--branch", branch]
        args += ["--", ref.url, str(dest)]
        run_git(args, timeout=timeout, token=token)
    size = dir_size_mb(dest)
    if size > max_mb:
        shutil.rmtree(dest, ignore_errors=True)
        raise RepositoryError(f"Repository is {size:.0f} MB which exceeds the {max_mb} MB limit")
    return run_git(["rev-parse", "HEAD"], cwd=dest)


class RepoWorkspace:
    """Read-only view over a checked-out repository with traversal-safe access."""

    MAX_FILE_BYTES = 1_000_000

    def __init__(self, root: Path):
        self.root = root.resolve()

    def path(self, rel: str) -> Path:
        return safe_join(self.root, rel)

    def rel(self, p: Path) -> str:
        return p.resolve().relative_to(self.root).as_posix()

    def iter_files(self, exts: set[str] | None = None, names: set[str] | None = None,
                   max_bytes: int | None = None) -> Iterator[Path]:
        limit = max_bytes or self.MAX_FILE_BYTES
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".sf_")]
            for f in files:
                p = Path(root) / f
                if p.is_symlink() or not is_within(self.root, p):
                    continue
                if exts is not None and p.suffix.lower() not in exts and (names is None or f not in names):
                    continue
                if exts is None and names is not None and f not in names:
                    continue
                try:
                    if p.stat().st_size > limit:
                        continue
                except OSError:
                    continue
                yield p

    def read_text(self, rel_or_path: str | Path) -> str:
        p = rel_or_path if isinstance(rel_or_path, Path) else self.path(rel_or_path)
        if not is_within(self.root, p):
            raise PathEscapeError(str(p))
        if p.stat().st_size > self.MAX_FILE_BYTES:
            raise RepositoryError(f"{p.name} exceeds read size limit")
        # Decode bytes directly so CRLF line endings survive and generated patches match the file on disk.
        return p.read_bytes().decode("utf-8", errors="replace")

    def exists(self, rel: str) -> bool:
        try:
            return self.path(rel).exists()
        except PathEscapeError:
            return False

    def languages(self) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for p in self.iter_files(set(LANG_BY_EXT)):
            counts[LANG_BY_EXT[p.suffix.lower()]] += 1
        return dict(counts.most_common())

    def primary_language(self) -> str:
        langs = {k: v for k, v in self.languages().items() if k != "terraform"}
        return next(iter(langs), "unknown")
