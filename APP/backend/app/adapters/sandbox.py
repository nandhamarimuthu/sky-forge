"""Docker-based sandbox for executing untrusted repository code (tests).

Isolation: a throwaway copy of the repo, --cap-drop ALL, no-new-privileges, memory/CPU/PID limits, and
`--network none` for the execution phase. Dependency installation runs in a separate container with network
access but writes only into the throwaway copy. If Docker is unavailable, execution is refused (fail closed).
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET  # noqa: S405 - parsing junit produced inside our own sandbox
from dataclasses import dataclass, field
from pathlib import Path

from app.adapters.repository.git_repo import SKIP_DIRS

log = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    status: str  # passed | failed | error | not_executed
    exit_code: int | None = None
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    coverage_percent: float | None = None
    coverage_files: dict[str, float] = field(default_factory=dict)
    missing_lines: dict[str, list[int]] = field(default_factory=dict)
    duration_s: float = 0.0
    failures: list[dict] = field(default_factory=list)
    log_tail: str = ""
    reason: str = ""


class DockerSandbox:
    def __init__(self, image: str, memory: str, cpus: str, timeout_s: int, enabled: bool = True,
                 cache_dir: Path | None = None):
        self.image = image
        self.memory = memory
        self.cpus = cpus
        self.timeout_s = timeout_s
        self.enabled = enabled
        self.cache_dir = cache_dir
        self._available: bool | None = None
        self._availability_checked_at = 0.0
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def _cache_key(self, work: Path, script: str) -> str | None:
        """Key on image + install script + requirement files; projects that install themselves are not cached."""
        if self.cache_dir is None or (work / "pyproject.toml").is_file() or (work / "setup.py").is_file():
            return None
        h = hashlib.sha256(f"{self.image}\n{script}".encode())
        for p in sorted(work.glob("requirements*.txt")) + sorted(work.glob("requirements/*.txt")):
            h.update(p.name.encode() + p.read_bytes())
        return h.hexdigest()[:24]

    def _lock(self, key: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(key, threading.Lock())

    def available(self) -> bool:
        if not self.enabled:
            return False
        now = time.monotonic()
        if self._available is True or (self._available is False and now - self._availability_checked_at < 5):
            return bool(self._available)
        exe = shutil.which("docker")
        if not exe:
            self._available = False
        else:
            try:
                r = subprocess.run([exe, "info", "--format", "{{.ServerVersion}}"], capture_output=True,
                                   text=True, timeout=15, check=False)
                self._available = r.returncode == 0
            except (subprocess.TimeoutExpired, OSError):
                self._available = False
        self._availability_checked_at = now
        return self._available

    def _ensure_image(self, image: str | None = None) -> None:
        image = image or self.image
        r = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=30, check=False)
        if r.returncode != 0:
            log.info("Pulling sandbox image %s", image)
            subprocess.run(["docker", "pull", "-q", image], capture_output=True, timeout=600, check=True)

    def toolchain(self, repo: Path, image: str, env: dict[str, str] | None = None) -> ToolchainSession:
        return ToolchainSession(self, repo, image, env or {})

    def _docker(self, work: Path, script: str, network: bool, timeout: int, image: str | None = None,
                env: dict[str, str] | None = None) -> tuple[int | None, str]:
        name = f"skyforge-sbx-{uuid.uuid4().hex[:10]}"
        cmd = ["docker", "run", "--rm", "--name", name, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--memory", self.memory, "--cpus", self.cpus, "--pids-limit", "512", "--read-only",
               "--tmpfs", "/tmp:rw,size=512m", "-e", "HOME=/tmp", "-e", "PIP_DISABLE_PIP_VERSION_CHECK=1",  # noqa: S108
               "-e", "PYTHONDONTWRITEBYTECODE=1", "-v", f"{work}:/work:rw", "-w", "/work"]
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        if not network:
            cmd += ["--network", "none"]
        cmd += [image or self.image, "sh", "-c", script]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            return r.returncode, (r.stdout + r.stderr)[-6000:]
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], capture_output=True, timeout=30, check=False)
            return None, f"Timed out after {timeout}s"

    @staticmethod
    def _copy(repo: Path, extra_files: dict[str, str] | None) -> Path:
        tmp = Path(tempfile.mkdtemp(prefix="skyforge-sbx-"))
        work = tmp / "work"
        shutil.copytree(repo, work, symlinks=False, ignore=shutil.ignore_patterns(*SKIP_DIRS))
        for rel, content in (extra_files or {}).items():
            target = (work / rel).resolve()
            if work.resolve() not in target.parents:
                raise ValueError(f"Refusing to write outside sandbox: {rel}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return work

    def session(self, repo: Path) -> SandboxSession:
        return SandboxSession(self, repo)

    def run_python_tests(self, repo: Path, *, test_paths: list[str] | None = None,
                         extra_files: dict[str, str] | None = None, coverage: bool = True) -> SandboxResult:
        if not self.available():
            return SandboxResult(status="not_executed", reason="Docker sandbox unavailable — execution refused")
        with self.session(repo) as s:
            for rel, content in (extra_files or {}).items():
                s.write_file(rel, content)
            err = s.install()
            if err:
                return err
            return s.pytest(test_paths, coverage=coverage)

    @staticmethod
    def _install_script(work: Path) -> str:
        # Tooling first so the project's own pins (e.g. an older httpx for its TestClient) take precedence.
        steps = ["python -m pip install -q --no-input --target /work/.sf_deps pytest==8.3.4 pytest-cov==6.0.0 "
                 "httpx==0.28.1"]
        for req in ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "requirements-test.txt",
                    "test-requirements.txt", "requirements/test.txt", "requirements/dev.txt"):
            if (work / req).is_file():
                steps.append(f"python -m pip install -q --no-input --upgrade --target /work/.sf_deps -r {req} || true")
        if (work / "pyproject.toml").is_file() or (work / "setup.py").is_file():
            steps.append("python -m pip install -q --no-input --upgrade --target /work/.sf_deps '.[test]' 2>/dev/null || "
                         "python -m pip install -q --no-input --upgrade --target /work/.sf_deps . || true")
        steps.append("PYTHONPATH=/work/.sf_deps python -c 'import pytest, pytest_cov'")
        return " ; ".join(steps)

    @staticmethod
    def _parse(work: Path, code: int | None, out: str) -> SandboxResult:
        res = SandboxResult(status="error", exit_code=code, log_tail=out[-3000:])
        junit = work / ".sf_junit.xml"
        if junit.exists():
            try:
                root = ET.parse(junit).getroot()  # noqa: S314
                suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
                for s in suites:
                    res.total += int(s.get("tests", 0))
                    res.failed += int(s.get("failures", 0))
                    res.errors += int(s.get("errors", 0))
                    res.skipped += int(s.get("skipped", 0))
                for case in root.iter("testcase"):
                    for tag in ("failure", "error"):
                        el = case.find(tag)
                        if el is not None and len(res.failures) < 25:
                            res.failures.append({"test": f"{case.get('classname')}::{case.get('name')}",
                                                 "type": tag, "message": (el.get("message") or "")[:400]})
                res.passed = max(0, res.total - res.failed - res.errors - res.skipped)
            except ET.ParseError:
                pass
        cov = work / ".sf_cov.json"
        if cov.exists():
            try:
                data = json.loads(cov.read_text())
                res.coverage_percent = round(float(data["totals"]["percent_covered"]), 1)
                for f, meta in data.get("files", {}).items():
                    if f.startswith(".sf_deps"):
                        continue
                    res.coverage_files[f] = round(float(meta["summary"]["percent_covered"]), 1)
                    res.missing_lines[f] = list(meta.get("missing_lines", []))[:400]
            except (KeyError, ValueError, json.JSONDecodeError):
                pass
        if code == 5 or (res.total == 0 and junit.exists()):
            res.status = "not_executed"
            res.reason = "No tests collected"
        elif code == 0:
            res.status = "passed"
        elif res.total:
            res.status = "failed"
        else:
            res.reason = "Test run errored before collecting results"
        return res


class SandboxSession:
    """One throwaway copy of the repo: install dependencies once, then run several isolated commands."""

    def __init__(self, sandbox: DockerSandbox, repo: Path):
        self.sb = sandbox
        self.repo = repo
        self.work: Path | None = None
        self.installed = False
        self.install_log = ""

    def __enter__(self) -> SandboxSession:
        self.work = DockerSandbox._copy(self.repo, None)
        return self

    def __exit__(self, *exc: object) -> None:
        if self.work is not None:
            shutil.rmtree(self.work.parent, ignore_errors=True)

    def write_file(self, rel: str, content: str) -> None:
        assert self.work is not None
        target = (self.work / rel).resolve()
        if self.work.resolve() not in target.parents:
            raise ValueError(f"Refusing to write outside sandbox: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def read_file(self, rel: str) -> str | None:
        assert self.work is not None
        p = (self.work / rel).resolve()
        if self.work.resolve() not in p.parents or not p.exists():
            return None
        return p.read_text(encoding="utf-8", errors="replace")

    def remove_file(self, rel: str) -> None:
        assert self.work is not None
        p = (self.work / rel).resolve()
        if self.work.resolve() in p.parents:
            p.unlink(missing_ok=True)

    def install(self) -> SandboxResult | None:
        """Returns an error result if installation failed, else None."""
        assert self.work is not None
        if not self.sb.available():
            return SandboxResult(status="not_executed", reason="Docker sandbox unavailable — execution refused")
        started = time.monotonic()
        try:
            self.sb._ensure_image()
        except (subprocess.SubprocessError, OSError) as exc:
            return SandboxResult(status="error", reason=f"Could not pull sandbox image: {exc}"[:500])
        script = DockerSandbox._install_script(self.work)
        key = self.sb._cache_key(self.work, script)
        if key is None:
            return self._install(script, started)
        cached = self.sb.cache_dir / key  # type: ignore[operator]
        with self.sb._lock(key):
            if not cached.is_dir():
                err = self._install(script, started)
                if err:
                    return err
                tmp = cached.with_name(f"{key}.tmp-{uuid.uuid4().hex[:6]}")
                cached.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(self.work / ".sf_deps", tmp, symlinks=True)
                tmp.rename(cached)
                return None
        shutil.copytree(cached, self.work / ".sf_deps", symlinks=True, dirs_exist_ok=True)
        self.install_log = f"Dependencies restored from cache {key}"
        self.installed = True
        return None

    def _install(self, script: str, started: float) -> SandboxResult | None:
        assert self.work is not None
        code, out = self.sb._docker(self.work, script, network=True, timeout=self.sb.timeout_s)
        self.install_log = out
        if code != 0:
            return SandboxResult(status="error", exit_code=code, reason="Dependency installation failed",
                                 log_tail=out[-3000:], duration_s=round(time.monotonic() - started, 1))
        self.installed = True
        return None

    def pytest(self, test_paths: list[str] | None = None, coverage: bool = True) -> SandboxResult:
        assert self.work is not None
        for leftover in (".sf_junit.xml", ".sf_cov.json"):
            (self.work / leftover).unlink(missing_ok=True)
        started = time.monotonic()
        targets = " ".join(f"'{t}'" for t in (test_paths or []))
        cov = "--cov=. --cov-report=json:/work/.sf_cov.json" if coverage else ""
        script = (f"PYTHONPATH=/work/.sf_deps:/work python -m pytest -q -p no:cacheprovider {cov} "
                  f"--junitxml=/work/.sf_junit.xml -o addopts='' --ignore=.sf_deps {targets}")
        code, out = self.sb._docker(self.work, script, network=False, timeout=self.sb.timeout_s)
        res = DockerSandbox._parse(self.work, code, out)
        res.duration_s = round(time.monotonic() - started, 1)
        return res

    def python(self, script_rel: str) -> tuple[int | None, str]:
        assert self.work is not None
        return self.sb._docker(self.work, f"PYTHONPATH=/work/.sf_deps:/work python '{script_rel}'", network=False,
                               timeout=self.sb.timeout_s)


class ToolchainSession(SandboxSession):
    """A throwaway repo copy executed with another language image (Node, Go, ...). Same isolation rules."""

    def __init__(self, sandbox: DockerSandbox, repo: Path, image: str, env: dict[str, str]):
        super().__init__(sandbox, repo)
        self.image = image
        self.env = env

    def __enter__(self) -> ToolchainSession:
        self.work = DockerSandbox._copy(self.repo, None)
        return self

    def prepare(self, install_script: str, cache_paths: list[str] | None = None,
                key_files: list[str] | None = None) -> SandboxResult | None:
        """Pull the image and run the dependency step with network, restoring/saving `cache_paths` keyed on
        `key_files`. Returns an error result on failure."""
        assert self.work is not None
        if not self.sb.available():
            return SandboxResult(status="not_executed", reason="Docker sandbox unavailable — execution refused")
        try:
            self.sb._ensure_image(self.image)
        except (subprocess.SubprocessError, OSError) as exc:
            return SandboxResult(status="error", reason=f"Could not pull {self.image}: {exc}"[:500])
        if not install_script:
            return None
        key = None
        if cache_paths and key_files and self.sb.cache_dir is not None:
            h = hashlib.sha256(f"{self.image}\n{install_script}".encode())
            for name in key_files:
                p = self.work / name
                h.update(name.encode() + (p.read_bytes() if p.is_file() else b"-"))
            key = "tc-" + h.hexdigest()[:24]
        if key is not None:
            cached = self.sb.cache_dir / key  # type: ignore[operator]
            with self.sb._lock(key):
                if cached.is_dir():
                    for rel in cache_paths or []:
                        if (cached / rel).is_dir():
                            shutil.copytree(cached / rel, self.work / rel, symlinks=True, dirs_exist_ok=True)
                    self.install_log = f"Dependencies restored from cache {key}"
                    return None
                err = self._prepare_run(install_script)
                if err is None:
                    tmp = cached.with_name(f"{key}.tmp-{uuid.uuid4().hex[:6]}")
                    for rel in cache_paths or []:
                        if (self.work / rel).is_dir():
                            shutil.copytree(self.work / rel, tmp / rel, symlinks=True)
                    tmp.mkdir(parents=True, exist_ok=True)
                    tmp.rename(cached)
                return err
        return self._prepare_run(install_script)

    def _prepare_run(self, install_script: str) -> SandboxResult | None:
        assert self.work is not None
        code, out = self.sb._docker(self.work, install_script, network=True, timeout=self.sb.timeout_s,
                                    image=self.image, env=self.env)
        self.install_log = out
        if code != 0:
            return SandboxResult(status="error", exit_code=code, reason="Dependency installation failed",
                                 log_tail=out[-3000:])
        return None

    def sh(self, script: str, timeout: int | None = None) -> tuple[int | None, str]:
        assert self.work is not None
        return self.sb._docker(self.work, script, network=False, timeout=timeout or self.sb.timeout_s,
                               image=self.image, env=self.env)
