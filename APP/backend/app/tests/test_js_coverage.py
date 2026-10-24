from __future__ import annotations

import json
import subprocess

import pytest

from app.adapters.sandbox import DockerSandbox


def sandbox(**kwargs):
    return DockerSandbox("python:3.11-slim", "512m", "1", 60, **kwargs)


def test_report(*, failed=0, total=2):
    return {
        "numTotalTests": total, "numPassedTests": total - failed, "numFailedTests": failed,
        "numPendingTests": 0,
        "testResults": [{"assertionResults": [
            {"fullName": "adds numbers", "status": "failed" if failed else "passed",
             "failureMessages": ["Expected 3, got 4"] if failed else []},
        ]}],
    }


test_report.__test__ = False


def coverage_file(hits, lines=None):
    lines = lines or list(range(1, len(hits) + 1))
    return {
        "s": {str(i): hit for i, hit in enumerate(hits)},
        "statementMap": {str(i): {"start": {"line": line, "column": 0},
                                  "end": {"line": line, "column": 10}}
                         for i, line in enumerate(lines)},
    }


def write_reports(work, *, tests=None, coverage=None):
    reports = work / ".sf_js_results"
    reports.mkdir(exist_ok=True)
    (reports / "tests.json").write_text(json.dumps(tests if tests is not None else test_report()))
    (reports / "coverage-final.json").write_text(json.dumps(
        coverage if coverage is not None else {"/work/src/add.js": coverage_file([1, 0])}))


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"devDependencies": {"jest": "27.0.6"}}))
    (root / "src").mkdir()
    (root / "src/add.js").write_text("exports.add = (a, b) => a + b;\n")
    return root


@pytest.fixture
def transport(monkeypatch):
    calls = []
    images = []
    monkeypatch.setattr(DockerSandbox, "available", lambda self: self.enabled)
    monkeypatch.setattr(DockerSandbox, "_ensure_image", lambda self: images.append(self.image))

    def configure(*, install_code=0, test_code=0, emit=write_reports):
        def docker(self, work, script, network, timeout):
            calls.append({"image": self.image, "work": work, "script": script, "network": network,
                          "timeout": timeout, "memory": self.memory, "cpus": self.cpus})
            if network:
                assert not (work / "node_modules/stale.js").exists()
                assert not (work / ".npmrc").exists()
                return install_code, "install output"
            if emit:
                emit(work)
            return test_code, "test output"
        monkeypatch.setattr(DockerSandbox, "_docker", docker)
        return calls, images
    return configure


@pytest.mark.parametrize("lockfile,command", [(None, "npm install"), ("package-lock.json", "npm ci"),
                                              ("npm-shrinkwrap.json", "npm ci")])
def test_install_and_execution_are_separate_isolated_stages(repo, transport, lockfile, command):
    if lockfile:
        (repo / lockfile).write_text("{}")
    (repo / "node_modules").mkdir()
    (repo / "node_modules/stale.js").write_text("throw Error('stale')")
    (repo / ".npmrc").write_text("ignore-scripts=false")
    calls, images = transport()
    sb = sandbox(node_image="node:custom")
    result = sb.run_javascript_tests(repo)
    assert result.status == "passed"
    assert result.framework == "jest"
    assert images == ["node:custom"]
    assert sb.image == "python:3.11-slim"
    assert [call["network"] for call in calls] == [True, False]
    assert all(call["image"] == "node:custom" for call in calls)
    assert all(call["timeout"] == 60 and call["memory"] == "512m" and call["cpus"] == "1" for call in calls)
    assert calls[0]["script"].startswith(command)
    assert "--ignore-scripts" in calls[0]["script"]
    assert "--include=dev" in calls[0]["script"]
    assert "npx" not in calls[1]["script"]
    assert "node ./node_modules/jest/bin/jest.js" in calls[1]["script"]
    assert "--collectCoverageFrom=" in calls[1]["script"]
    assert "**/*.{js,jsx,ts,tsx,mjs,cjs,mts,cts}" in calls[1]["script"]
    assert "__tests__" in calls[1]["script"]
    assert "generated" in calls[1]["script"]
    assert calls[0]["work"] != repo
    assert not calls[0]["work"].exists()
    assert (repo / "node_modules/stale.js").exists()
    assert not (repo / ".sf_js_results").exists()


def test_weighted_coverage_and_duplicate_statements_on_same_line(repo, transport):
    def emit(work):
        write_reports(work, coverage={
            "/work/src/add.js": coverage_file([0, 2, 1], lines=[1, 1, 2]),
            "/work/src/unused.ts": coverage_file([0] * 8),
        })
    transport(emit=emit)
    result = sandbox().run_javascript_tests(repo)
    assert result.coverage_percent == 20.0
    assert result.total_lines == 10
    assert result.covered_lines == 2
    assert result.coverage_files == {"src/add.js": 100.0, "src/unused.ts": 0.0}
    assert result.statements == {"src/add.js": 2, "src/unused.ts": 8}
    assert result.missing_counts == {"src/add.js": 0, "src/unused.ts": 8}
    assert result.missing_lines["src/unused.ts"] == list(range(1, 9))


def test_measured_zero_is_not_unknown(repo, transport):
    transport(emit=lambda work: write_reports(work, coverage={"/work/src/add.js": coverage_file([0, 0])}))
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "passed"
    assert result.coverage_percent == 0.0
    assert result.covered_lines == 0
    assert result.total_lines == 2


def test_failed_tests_keep_valid_coverage(repo, transport):
    transport(test_code=1, emit=lambda work: write_reports(work, tests=test_report(failed=1)))
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "failed"
    assert result.total == 2 and result.passed == 1 and result.failed == 1
    assert result.coverage_percent == 50.0
    assert result.failures[0]["test"] == "adds numbers"


@pytest.mark.parametrize("code", [1, None])
def test_installation_failure_never_executes_tests(repo, transport, code):
    calls, _ = transport(install_code=code)
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "error"
    assert result.coverage_percent is None
    assert "installation failed" in result.reason
    assert len(calls) == 1


def test_missing_reports_do_not_accept_stale_repo_coverage(repo, transport):
    write_reports(repo)
    (repo / "coverage").mkdir()
    (repo / "coverage/coverage-final.json").write_text('{"stale": "report"}')
    transport(emit=None)
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "error"
    assert result.coverage_percent is None
    assert "test report" in result.reason
    assert (repo / ".sf_js_results/coverage-final.json").exists()


def test_install_stage_reports_are_removed(repo, monkeypatch):
    monkeypatch.setattr(DockerSandbox, "available", lambda self: True)
    monkeypatch.setattr(DockerSandbox, "_ensure_image", lambda self: None)

    def docker(self, work, script, network, timeout):
        if network:
            write_reports(work)
        else:
            assert list((work / ".sf_js_results").iterdir()) == []
        return 0, ""
    monkeypatch.setattr(DockerSandbox, "_docker", docker)
    assert sandbox().run_javascript_tests(repo).coverage_percent is None


@pytest.mark.parametrize("filename,content", [
    ("tests.json", None), ("tests.json", "{bad"), ("tests.json", "[]"), ("tests.json", "{}"),
    ("coverage-final.json", None), ("coverage-final.json", "{bad"), ("coverage-final.json", "[]"),
    ("coverage-final.json", "{}"), ("coverage-final.json", '{"src/add.js": {}}'),
    ("coverage-final.json", '{"src/add.js": {"s": {"0": 1}, "statementMap": {}}}'),
])
def test_missing_or_malformed_reports_fail_explicitly(repo, transport, filename, content):
    def emit(work):
        write_reports(work)
        path = work / ".sf_js_results" / filename
        if content is None:
            path.unlink()
        else:
            path.write_text(content)
    transport(emit=emit)
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "error"
    assert result.reason
    assert result.coverage_percent is None
    assert result.coverage_files == {}
    assert result.total_lines is None


def test_partial_malformed_coverage_does_not_leak_partial_measurement(repo, transport):
    transport(emit=lambda work: write_reports(work, coverage={
        "/work/src/add.js": coverage_file([1]), "/work/src/bad.js": coverage_file([-1]),
    }))
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "error"
    assert result.coverage_files == {}
    assert result.coverage_percent is None


def test_no_executable_lines_is_unknown_not_one_hundred_percent(repo, transport):
    transport(emit=lambda work: write_reports(work, coverage={"/work/src/empty.js": coverage_file([])}))
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "error"
    assert result.coverage_percent is None
    assert result.total_lines is None


def test_no_tests_collected_is_not_executed(repo, transport):
    transport(emit=lambda work: write_reports(work, tests=test_report(total=0)))
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "not_executed"
    assert result.reason == "No tests collected"


def test_inconsistent_test_counts_reject_measurement(repo, transport):
    tests = test_report()
    tests["numPassedTests"] = 100
    transport(emit=lambda work: write_reports(work, tests=tests))
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "error"
    assert result.coverage_percent is None


def test_reports_cannot_reference_host_paths(repo, transport):
    transport(emit=lambda work: write_reports(work, coverage={"/outside/add.js": coverage_file([1])}))
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "error"
    assert result.coverage_percent is None


@pytest.mark.parametrize("code", [1, None])
def test_execution_errors_keep_status_error(repo, transport, code):
    transport(test_code=code)
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "error"
    assert "execution" in result.reason


def test_disabled_sandbox_refuses_execution(repo, transport):
    calls, _ = transport()
    result = sandbox(enabled=False).run_javascript_tests(repo)
    assert result.status == "not_executed"
    assert "unavailable" in result.reason
    assert calls == []


@pytest.mark.parametrize("manifest", [None, "{", "[]", "{}", '{"devDependencies":{"mocha":"10"}}'])
def test_missing_manifest_or_unsupported_runner(repo, transport, manifest):
    calls, _ = transport()
    path = repo / "package.json"
    if manifest is None:
        path.unlink()
    else:
        path.write_text(manifest)
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "not_executed"
    assert result.coverage_percent is None
    assert result.reason
    assert calls == []


@pytest.mark.parametrize("provider", ["v8", "istanbul"])
def test_vitest_uses_existing_provider_without_download(repo, transport, provider):
    (repo / "package.json").write_text(json.dumps({
        "devDependencies": {"vitest": "^3.0.0", f"@vitest/coverage-{provider}": "^3.0.0"},
    }))
    calls, _ = transport()
    result = sandbox().run_javascript_tests(repo)
    assert result.framework == "vitest"
    assert result.status == "passed"
    assert f"--coverage.provider={provider}" in calls[1]["script"]
    assert "--coverage.include=" in calls[1]["script"]
    assert "--coverage.all" in calls[1]["script"]
    assert "npx" not in calls[1]["script"]


def test_vitest_without_provider_refuses_automatic_download(repo, transport):
    (repo / "package.json").write_text('{"devDependencies":{"vitest":"3.0.0"}}')
    calls, _ = transport()
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "not_executed"
    assert "automatic downloads refused" in result.reason
    assert calls == []


def test_image_failure_is_explicit(repo, transport, monkeypatch):
    calls, _ = transport()

    def fail(self):
        raise subprocess.CalledProcessError(1, ["docker", "pull"])
    monkeypatch.setattr(DockerSandbox, "_ensure_image", fail)
    result = sandbox().run_javascript_tests(repo)
    assert result.status == "error"
    assert result.coverage_percent is None
    assert calls == []


def test_docker_command_preserves_isolation(repo, monkeypatch):
    commands = []

    def run(cmd, **kwargs):
        commands.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(subprocess, "run", run)
    sb = sandbox()
    sb._docker(repo, "npm ci --ignore-scripts", network=True, timeout=60)
    sb._docker(repo, "node ./node_modules/jest/bin/jest.js", network=False, timeout=60)
    for cmd in commands:
        for expected in ["--cap-drop", "ALL", "no-new-privileges", "--memory", "512m", "--cpus",
                         "--pids-limit", "--read-only"]:
            assert expected in cmd
    assert "--network" not in commands[0]
    assert commands[1][commands[1].index("--network") + 1] == "none"
