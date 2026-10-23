from __future__ import annotations

import threading
from typing import Any

import pytest

from app.adapters.aws.dump import DumpAwsAdapter
from app.adapters.sandbox import DockerSandbox
from app.adapters.scanners.manifests import upgrade_patch
from app.adapters.scanners.terraform import parse_terraform
from app.agents import AGENTS
from app.agents.base import AgentContext, ToolPermissionError
from app.agents.security_guardrails import PolicyEngine
from app.core.config import get_settings
from app.tests.conftest import FakeOSV


def make_ctx(ws, agent_id: str, options: dict | None = None) -> tuple[AgentContext, list]:
    events: list[tuple[str, str, dict[str, Any]]] = []
    tools = {"repo.read": ws, "osv.query": FakeOSV(), "manifest.patch": upgrade_patch,
             "sandbox.execute": DockerSandbox("python:3.11-slim", "1g", "1", 60, enabled=False),
             "static.ruff": True, "static.radon": True, "terraform.parse": parse_terraform,
             "aws.read": lambda hints=None: DumpAwsAdapter(get_settings().fixtures_dir / "aws" / "demo-shop",
                                                           "demo-shop", hints),
             "llm.generate": None}
    ctx = AgentContext(scan_id="scan_test", project={"id": "p", "aws": {"account_id": "123456789012"}}, workspace=ws,
                       options=options or {"execute_tests": True, "generate_tests": True}, tools=tools,
                       allowed_tools=AGENTS[agent_id].allowed_tools,
                       emit=lambda t, m="", **kw: events.append((t, m, kw)), cancel_event=threading.Event(),
                       agent_id=agent_id)
    return ctx, events


def test_tool_permissions_are_enforced(fixture_ws):
    ctx, events = make_ctx(fixture_ws, "code_health")
    with pytest.raises(ToolPermissionError):
        ctx.tool("aws.read")
    assert any("DENIED" in m for _, m, _ in events)


def test_vulnerability_agent_proposes_valid_patches(fixture_ws):
    ctx, _ = make_ctx(fixture_ws, "vulnerability")
    res = AGENTS["vulnerability"].run(ctx)
    names = {f.evidence["package"] for f in res.findings}
    assert {"requests", "urllib3", "flask", "werkzeug"} <= names
    req = next(f for f in res.findings if f.evidence["package"] == "requests")
    assert req.proposal and "+requests==2.31.0" in req.proposal.diff
    assert PolicyEngine(fixture_ws).validate(req.proposal)["passed"]


def test_guardrails_agent_detects_policy_violations(fixture_ws):
    ctx, _ = make_ctx(fixture_ws, "guardrails")
    res = AGENTS["guardrails"].run(ctx)
    rules = {f.rule_id for f in res.findings}
    for expected in ("code:py-yaml-load", "code:py-tls-verify-off", "code:py-shell-true", "iac:open-ingress",
                     "iac:s3-public-acl", "iac:rds-public", "docker:runs-as-root", "secret:aws_access_key_id"):
        assert expected in rules, expected
    open_ingress = next(f for f in res.findings if f.rule_id == "iac:open-ingress")
    assert open_ingress.severity == "critical"
    # every generated fix must pass the policy engine
    for f in res.findings:
        if f.proposal:
            assert PolicyEngine(fixture_ws).validate(f.proposal)["passed"], (f.rule_id, f.proposal.diff)


def test_code_health_agent_metrics(fixture_ws):
    ctx, _ = make_ctx(fixture_ws, "code_health")
    res = AGENTS["code_health"].run(ctx)
    assert res.metrics["max_complexity"] >= 15
    assert any(f.rule_id == "health:complexity" and "process_order" in f.title for f in res.findings)


def test_aws_agent_iac_patches_pass_policy(fixture_ws):
    ctx, _ = make_ctx(fixture_ws, "aws_optimizer")
    res = AGENTS["aws_optimizer"].run(ctx)
    assert res.metrics["estimated_monthly_savings"] > 0
    iac = [f for f in res.findings if f.proposal and f.proposal.kind == "iac_change"]
    assert iac
    for f in iac:
        assert PolicyEngine(fixture_ws).validate(f.proposal)["passed"]


def test_aws_agent_on_one_month_data_dump(fixture_ws, settings):
    ctx, _ = make_ctx(fixture_ws, "aws_optimizer")
    ctx.tools["aws.read"] = lambda hints=None: DumpAwsAdapter(settings.fixtures_dir / "aws" / "demo-shop", "demo-shop",
                                                              hints)
    res = AGENTS["aws_optimizer"].run(ctx)
    rules = {f.rule_id for f in res.findings}
    for expected in ("aws:ec2-idle", "aws:ec2-rightsize", "aws:ebs-unattached", "aws:rds-rightsize", "aws:nat-idle",
                     "aws:elb-idle", "aws:snapshot-old", "aws:cost-anomaly"):
        assert expected in rules, expected
    assert res.metrics["simulated"] is False and res.metrics["spend"]["measured"] is True
    assert res.metrics["data_source"]["period_start"] == "2026-09-22"
    rightsize = next(f for f in res.findings if f.rule_id == "aws:ec2-rightsize" and f.target == "aws_instance.api")
    assert rightsize.proposal and '+  instance_type = "m5.xlarge"' in rightsize.proposal.diff
    assert rightsize.evidence["actual_monthly_cost"] > 0 and rightsize.evidence["period_days"] == 30


def test_unit_test_agent_without_sandbox_fails_closed(fixture_ws):
    ctx, _ = make_ctx(fixture_ws, "unit_test")
    res = AGENTS["unit_test"].run(ctx)
    assert res.test_runs and res.test_runs[0].status == "not_executed"
    assert res.metrics["sandbox_executed"] is False
    assert any(f.category == "coverage" for f in res.findings)


def test_functional_agent_generates_suite(fixture_ws):
    ctx, _ = make_ctx(fixture_ws, "functional_test")
    res = AGENTS["functional_test"].run(ctx)
    suite = next(f for f in res.findings if f.proposal)
    assert "def test_post_quote_does_not_error" in suite.proposal.diff
    assert "requires_authentication" in suite.proposal.diff
    assert PolicyEngine(fixture_ws).validate(suite.proposal)["passed"]


def test_codemod_diff_ending_on_blank_context_line_still_applies(settings, tmp_path):
    from app.adapters.repository.git_repo import RepoWorkspace, materialize, parse_repo_url
    from app.agents.security_guardrails import code_fix

    dest = tmp_path / "orders"
    materialize(parse_repo_url("fixture:orders-api", settings.git_hosts, settings.fixtures_dir), dest, branch=None,
                fixtures_dir=settings.fixtures_dir, timeout=60, max_mb=50)
    ws = RepoWorkspace(dest)
    line = next(i for i, ln in enumerate(ws.read_text("orders_api/integrations.py").splitlines(), 1)
                if "verify=False" in ln)
    prop = code_fix(ws, "py-tls-verify-off", "orders_api/integrations.py", line)
    assert prop and prop.diff.endswith("\n")
    assert PolicyEngine(ws).validate(prop)["passed"]

    ctx, _ = make_ctx(ws, "aws_optimizer")
    ctx.tools["aws.read"] = lambda hints=None: DumpAwsAdapter(settings.fixtures_dir / "aws" / "orders-api",
                                                              "orders-api", hints)
    res = AGENTS["aws_optimizer"].run(ctx)
    rds = next(f for f in res.findings if f.rule_id == "aws:rds-rightsize")
    assert rds.target == "aws_db_instance.reporting" and "db.t3.large" in rds.title
    assert rds.proposal and PolicyEngine(ws).validate(rds.proposal)["passed"]


def test_ruff_message_without_changes_is_not_a_diff():
    from app.adapters.scanners.code_metrics import _normalize_ruff_diff

    assert _normalize_ruff_diff("No errors would be fixed (1 fix available with `--unsafe-fixes`).\n") == ""


def test_drop_failing_llm_tests_keeps_the_rest():
    from app.agents.unit_test_agent import _drop_tests

    code = ("import pytest\n\n\ndef test_ok():\n    assert 1 == 1\n\n\n@pytest.mark.parametrize('x', [1])\n"
            "def test_bad(x):\n    assert x == 2\n")
    out = _drop_tests(code, {"test_bad"})
    assert out is not None and "def test_ok" in out and "test_bad" not in out and "parametrize" not in out
