"""Docker-based sandbox for executing untrusted repository code (tests).

Isolation: a throwaway copy of the repo, --cap-drop ALL, no-new-privileges, memory/CPU/PID limits, and
`--network none` for the execution phase. Dependency installation runs in a separate container with network
access but writes only into the throwaway copy. If Docker is unavailable, execution is refused (fail closed).
"""

from __future__ import annotations

import json
import logging
import shlex
import shutil
import subprocess
import tempfile
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
    statements: dict[str, int] = field(default_factory=dict)
    missing_counts: dict[str, int] = field(default_factory=dict)
    duration_s: float = 0.0
    failures: list[dict] = field(default_factory=list)
    log_tail: str = ""
    reason: str = ""
    framework: str = "pytest"
    covered_lines: int | None = None
    total_lines: int | None = None


class DockerSandbox:
    #: Host-side pip wheel cache, shared by every sandbox run so repeat scans skip re-downloading wheels.
    CACHE_VOLUME = "skyforge-pip-cache"

    def __init__(self, image: str, memory: str, cpus: str, timeout_s: int, enabled: bool = True,
                 node_image: str = "node:22-slim"):
        self.image = image
        self.node_image = node_image
        self.memory = memory
        self.cpus = cpus
        self.timeout_s = timeout_s
        self.enabled = enabled
        self._available: bool | None = None
        self._image_ready = False

    def available(self) -> bool:
        if not self.enabled:
            return False
        if self._available is None:
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
        return self._available

    def _ensure_image(self) -> None:
        if self._image_ready:
            return
        r = subprocess.run(["docker", "image", "inspect", self.image], capture_output=True, timeout=30, check=False)
        if r.returncode != 0:
            log.info("Pulling sandbox image %s", self.image)
            subprocess.run(["docker", "pull", "-q", self.image], capture_output=True, timeout=600, check=True)
        self._image_ready = True

    def _docker(self, work: Path, script: str, network: bool, timeout: int) -> tuple[int | None, str]:
        name = f"skyforge-sbx-{uuid.uuid4().hex[:10]}"
        cmd = ["docker", "run", "--rm", "--name", name, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--memory", self.memory, "--cpus", self.cpus, "--pids-limit", "512", "--read-only",
               "--tmpfs", "/tmp:rw,size=512m", "-e", "HOME=/tmp", "-e", "PIP_DISABLE_PIP_VERSION_CHECK=1",  # noqa: S108
               "-e", "PYTHONDONTWRITEBYTECODE=1", "-v", f"{work}:/work:rw", "-w", "/work"]
        if network:
            # Wheel cache only matters for the install phase, which is the only phase with network access.
            cmd += ["-v", f"{self.CACHE_VOLUME}:/pipcache", "-e", "PIP_CACHE_DIR=/pipcache"]
        else:
            cmd += ["--network", "none"]
        cmd += [self.image, "sh", "-c", script]
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

    def run_javascript_tests(self, repo: Path) -> SandboxResult:
        """Measure line coverage using the repository's installed Jest or Vitest, never host Node."""
        started = time.monotonic()
        framework = "unknown"
        try:
            try:
                manifest = json.loads((repo / "package.json").read_text(encoding="utf-8"))
                deps = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
            except (OSError, ValueError, TypeError, AttributeError):
                return SandboxResult(status="not_executed", framework=framework,
                                     reason="Missing or malformed package.json")
            framework = next((runner for runner in ("jest", "vitest") if runner in deps), "unknown")
            if framework == "unknown":
                return SandboxResult(status="not_executed", framework=framework,
                                     reason="No supported test runner declared (Jest or Vitest required)")
            provider = "v8" if "@vitest/coverage-v8" in deps else "istanbul"
            if framework == "vitest" and f"@vitest/coverage-{provider}" not in deps:
                return SandboxResult(status="not_executed", framework=framework,
                                     reason="Vitest coverage requires an existing @vitest/coverage-v8 or "
                                            "@vitest/coverage-istanbul dependency; automatic downloads refused")
            node = DockerSandbox(self.node_image, self.memory, self.cpus, self.timeout_s, enabled=self.enabled)
            if not node.available():
                return SandboxResult(status="not_executed", framework=framework,
                                     reason="Docker sandbox unavailable — execution refused")
            node._ensure_image()
            with tempfile.TemporaryDirectory(prefix=".sf-js-", dir=repo.resolve().parent) as scratch:
                work = Path(scratch) / "work"
                shutil.copytree(repo, work, symlinks=False,
                                ignore=shutil.ignore_patterns(*SKIP_DIRS, ".sf_*", ".npmrc"))
                install = "ci" if any((work / p).is_file() for p in ("package-lock.json", "npm-shrinkwrap.json")) else "install"
                code, out = node._docker(
                    work, f"npm {install} --ignore-scripts --include=dev --no-audit --no-fund --cache /work/.sf_npm",
                    network=True, timeout=self.timeout_s)
                if code != 0:
                    return SandboxResult(status="error", framework=framework, exit_code=code,
                                         reason="JavaScript dependency installation failed", log_tail=out[-3000:],
                                         duration_s=round(time.monotonic() - started, 1))
                reports = work / ".sf_js_results"
                if reports.is_symlink() or reports.is_file():
                    reports.unlink()
                elif reports.exists():
                    shutil.rmtree(reports)
                reports.mkdir()
                script = self._javascript_test_script(framework, provider)
                code, out = node._docker(work, script, network=False, timeout=self.timeout_s)
                res = self._parse_javascript(work, framework, code, out)
                res.duration_s = round(time.monotonic() - started, 1)
                return res
        except (OSError, subprocess.SubprocessError, shutil.Error) as exc:
            return SandboxResult(status="error", framework=framework,
                                 reason=f"JavaScript sandbox failed: {exc}"[:500],
                                 duration_s=round(time.monotonic() - started, 1))

    @staticmethod
    def _javascript_test_script(framework: str, provider: str) -> str:
        include = "**/*.{js,jsx,ts,tsx,mjs,cjs,mts,cts}"
        exclude = [
            "**/node_modules/**", "**/.*/**", "**/{dist,build,coverage,out,.next,generated,vendor}/**",
            "**/{test,tests,__tests__,__mocks__,unit-tests,functional-tests,e2e,fixtures}/**",
            "**/*.{test,spec}.{js,jsx,ts,tsx,mjs,cjs,mts,cts}", "**/*.d.{ts,mts,cts}",
            "**/*.{config,generated}.{js,jsx,ts,tsx,mjs,cjs,mts,cts}", "**/test-*.{js,ts}",
        ]
        directory = "/work/.sf_js_results"
        if framework == "jest":
            args = [
                "--runInBand", "--watch=false", "--watchAll=false", "--ci", "--coverage",
                "--coverageProvider=babel", "--coverageReporters=json", f"--coverageDirectory={directory}",
                "--collectCoverageFrom=" + json.dumps([include, *["!" + pattern for pattern in exclude]]),
                "--coveragePathIgnorePatterns=/node_modules/", "--json", f"--outputFile={directory}/tests.json",
            ]
            return "node ./node_modules/jest/bin/jest.js " + " ".join(map(shlex.quote, args))
        args = [
            "run", "--coverage.enabled", f"--coverage.provider={provider}", "--coverage.reporter=json",
            "--coverage.reportOnFailure", f"--coverage.reportsDirectory={directory}",
            f"--coverage.include={include}", "--reporter=json", f"--outputFile={directory}/tests.json",
            *[f"--coverage.exclude={pattern}" for pattern in exclude],
        ]
        # Vitest 4 always includes matching unimported files; older releases require coverage.all.
        driver = (
            "const fs=require('node:fs');const {spawnSync}=require('node:child_process');"
            "const v=JSON.parse(fs.readFileSync('./node_modules/vitest/package.json','utf8')).version;"
            f"const args={json.dumps(args)};"
            "if(parseInt(v,10)<4)args.push('--coverage.all');"
            "const r=spawnSync(process.execPath,['./node_modules/vitest/vitest.mjs',...args],"
            "{stdio:'inherit',env:{...process.env,CI:'true'}});process.exit(r.status??1);"
        )
        return "node -e " + shlex.quote(driver)

    @staticmethod
    def _parse_javascript(work: Path, framework: str, code: int | None, out: str) -> SandboxResult:
        res = SandboxResult(status="error", framework=framework, exit_code=code, log_tail=out[-3000:])

        def count(value: object) -> int:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("Invalid nonnegative integer in report")
            return value

        def report(name: str) -> dict:
            path = work / ".sf_js_results" / name
            if work.resolve() not in path.resolve().parents:
                raise ValueError("Report points outside sandbox")
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Report is not an object")
            return data

        try:
            tests = report("tests.json")
            res.total = count(tests["numTotalTests"])
            res.passed = count(tests["numPassedTests"])
            res.failed = count(tests["numFailedTests"])
            res.skipped = count(tests["numPendingTests"]) + count(tests.get("numTodoTests", 0))
            res.errors = count(tests.get("numRuntimeErrorTestSuites", 0))
            if res.total != res.passed + res.failed + res.skipped:
                raise ValueError("Inconsistent test counts")
            for suite in tests["testResults"]:
                for case in suite["assertionResults"]:
                    if case.get("status") == "failed" and len(res.failures) < 25:
                        res.failures.append({"test": case.get("fullName", case.get("title", "")),
                                             "type": "failure",
                                             "message": "\n".join(case.get("failureMessages", []))[:400]})
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            res.reason = "Missing or malformed JavaScript test report"
            return res
        try:
            data = report("coverage-final.json")
            covered = 0
            total = 0
            files: dict[str, float] = {}
            missing: dict[str, list[int]] = {}
            statements: dict[str, int] = {}
            missing_counts: dict[str, int] = {}
            for filename, meta in data.items():
                path = Path(filename)
                if path.is_absolute():
                    path = path.relative_to("/work")
                if ".." in path.parts or path.as_posix() in files:
                    raise ValueError("Invalid coverage path")
                filename = path.as_posix()
                if not isinstance(meta["s"], dict) or set(meta["s"]) != set(meta["statementMap"]):
                    raise ValueError("Inconsistent statement map")
                lines: dict[int, int] = {}
                for statement, hits in meta["s"].items():
                    line = count(meta["statementMap"][statement]["start"]["line"])
                    if line == 0:
                        raise ValueError("Invalid line number")
                    # Istanbul line coverage uses statement start lines and max hits per line.
                    lines[line] = max(lines.get(line, 0), count(hits))
                if not lines:
                    continue
                uncovered = sorted(line for line, hits in lines.items() if hits == 0)
                measured = len(lines)
                hit = measured - len(uncovered)
                total += measured
                covered += hit
                files[filename] = round(100 * hit / measured, 1)
                missing[filename] = uncovered[:400]
                statements[filename] = measured
                missing_counts[filename] = len(uncovered)
            if not total:
                raise ValueError("No executable source lines measured")
            res.total_lines, res.covered_lines = total, covered
            res.coverage_percent = round(100 * covered / total, 1)
            res.coverage_files, res.missing_lines = files, missing
            res.statements, res.missing_counts = statements, missing_counts
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            res.reason = "Missing, malformed, or empty JavaScript coverage report"
            return res
        if code is None:
            res.reason = "JavaScript test execution timed out"
        elif not res.total:
            res.status, res.reason = "not_executed", "No tests collected"
        elif res.failed or res.errors:
            res.status = "failed"
        elif code != 0:
            res.reason = "JavaScript test execution failed"
        else:
            res.status = "passed"
        return res

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
                    res.statements[f] = int(meta["summary"].get("num_statements", 0))
                    res.missing_counts[f] = int(meta["summary"].get("missing_lines",
                                                                    len(meta.get("missing_lines", []))))
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
        code, out = self.sb._docker(self.work, DockerSandbox._install_script(self.work), network=True,
                                    timeout=self.sb.timeout_s)
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
