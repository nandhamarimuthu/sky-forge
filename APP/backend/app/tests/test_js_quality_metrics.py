from __future__ import annotations

import threading

import pytest

from app.adapters.repository.git_repo import RepoWorkspace
from app.adapters.sandbox import SandboxResult
from app.agents.base import AgentContext
from app.agents.code_health_agent import CodeHealthAgent
from app.agents.unit_test_agent import UnitTestAgent
from app.db.session import session_scope
from app.models import AgentRun, Scan, utcnow
from app.tests.conftest import ENGINEER, VIEWER
from app.tests.test_code_health_pr import sources


def _context(ws, agent, tools, options=None):
    return AgentContext(scan_id="s", project={}, workspace=ws, options=options or {},
                        tools={"repo.read": ws, **tools}, allowed_tools=agent.allowed_tools,
                        emit=lambda *args, **kwargs: None, cancel_event=threading.Event())


@pytest.mark.parametrize("percent", [0.0, 42.5])
def test_js_coverage_is_persisted_in_metrics_and_test_run(tmp_path, percent):
    (tmp_path / "math.js").write_text("function add(a, b) { return a + b; }\nmodule.exports = { add };\n")
    calls = []

    class Sandbox:
        def run_javascript_tests(self, root):
            calls.append(root)
            return SandboxResult(status="passed", exit_code=0, framework="jest", total=2, passed=2,
                                 coverage_percent=percent, coverage_files={"math.js": percent})

    agent = UnitTestAgent()
    result = agent.run(_context(RepoWorkspace(tmp_path), agent, {"sandbox.execute": Sandbox()}))
    assert calls == [tmp_path]
    assert result.metrics["coverage_before"] == percent
    assert result.metrics["coverage_after"] is None
    assert result.metrics["source_files"] == 1
    assert result.test_runs[0].framework == "jest"
    assert result.test_runs[0].coverage_after == percent


def test_disabled_js_execution_does_not_invent_coverage(tmp_path):
    (tmp_path / "app.ts").write_text("export function add(a: number, b: number) { return a + b; }\n")
    agent = UnitTestAgent()
    result = agent.run(_context(RepoWorkspace(tmp_path), agent, {}, {"execute_tests": False}))
    assert result.metrics["coverage_before"] is None
    assert result.test_runs[0].status == "not_executed"
    assert "disabled" in result.test_runs[0].details["reason"]


def test_mixed_language_coverage_is_weighted_by_source_lines():
    py = SandboxResult(status="passed", coverage_percent=100, statements={"a.py": 10})
    js = SandboxResult(status="failed", coverage_percent=0, statements={"a.js": 90})
    assert UnitTestAgent._coverage(py, js) == 10.0
    assert UnitTestAgent._coverage(None, js) == 0.0


def test_js_health_uses_js_source_lines(tmp_path):
    before = sources()
    for path, text in before.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    agent = CodeHealthAgent()
    result = agent.run(_context(RepoWorkspace(tmp_path), agent, {"static.ruff": True, "static.radon": True}))
    assert result.metrics["python_modules"] == 0
    assert result.metrics["javascript_modules"] == 3
    assert result.metrics["sloc"] == sum(sum(bool(line.strip()) for line in text.splitlines()) for text in before.values())
    assert 0 < result.metrics["duplication_pct"] <= 100
    assert 0 < result.metrics["health_score"] <= 100


def test_unrelated_scan_does_not_clear_quality_metrics_or_zero_coverage(client):
    response = client.post("/api/v1/projects", headers=ENGINEER, json={
        "name": "Retained quality measurements", "repo_url": "fixture:demo-shop",
    })
    assert response.status_code == 201
    pid = response.json()["id"]
    with session_scope() as db:
        initial = Scan(project_id=pid, requested_by="bob", status="completed")
        db.add(initial)
        db.flush()
        db.add_all([
            AgentRun(scan_id=initial.id, project_id=pid, agent_id="unit_test", status="completed",
                     metrics={"coverage_before": 40.0, "coverage_after": 0.0}, finished_at=utcnow()),
            AgentRun(scan_id=initial.id, project_id=pid, agent_id="code_health", status="completed",
                     metrics={"health_score": 87}, finished_at=utcnow()),
        ])
        db.add(Scan(project_id=pid, requested_by="bob", status="completed", agents=["guardrails"],
                    summary={"coverage": None, "health_score": None}))
    project = client.get(f"/api/v1/projects/{pid}", headers=VIEWER).json()
    assert project["stats"]["coverage"] == 0.0
    assert project["stats"]["coverage_before"] == 40.0
    assert project["stats"]["health_score"] == 87
    dashboard = client.get("/api/v1/dashboard/summary", headers=VIEWER).json()
    item = next(p for p in dashboard["per_project"] if p["id"] == pid)
    assert item["coverage"] == 0.0 and item["health_score"] == 87
