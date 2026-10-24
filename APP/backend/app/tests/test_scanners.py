from __future__ import annotations

from app.adapters.aws.dump import DumpAwsAdapter
from app.adapters.scanners.code_metrics import analyse_python_module, discover_python_routes
from app.adapters.scanners.manifests import discover_dependencies, upgrade_patch
from app.adapters.scanners.osv import (
    Advisory,
    cvss3_base_score,
    is_major_bump,
    minimal_safe_version,
    score_to_severity,
)
from app.adapters.scanners.terraform import parse_terraform
from app.agents.aws_optimizer_agent import detect_anomalies
from app.agents.unit_test_agent import build_cases


def test_cvss3_scores():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("garbage") is None
    assert score_to_severity(9.8) == "critical" and score_to_severity(5.0) == "medium"


def _adv(fixed: list[str]) -> Advisory:
    return Advisory(id="X", aliases=[], summary="", severity="high", cvss_score=None, fixed_versions=fixed,
                    references=[], published=None)


def test_minimal_safe_version_and_major_bump():
    assert minimal_safe_version("PyPI", "2.25.1", [_adv(["2.31.0"]), _adv(["2.26.0"])]) == "2.31.0"
    assert minimal_safe_version("PyPI", "1.0", [_adv([])]) is None
    assert is_major_bump("PyPI", "1.26.4", "2.0.7") and not is_major_bump("PyPI", "2.25.1", "2.31.0")
    assert is_major_bump("npm", "0.21.1", "0.28.0")


def test_manifest_discovery_and_patch(fixture_ws):
    deps = {d.name: d for d in discover_dependencies(fixture_ws)}
    assert deps["requests"].version == "2.25.1" and deps["requests"].pinned
    diff = upgrade_patch(fixture_ws, deps["requests"], "2.31.0")
    assert diff and "-requests==2.25.1" in diff and "+requests==2.31.0" in diff
    assert diff.count("\n+") == 2  # header + one changed line


def test_terraform_parse(fixture_ws):
    res = {r.address: r for r in parse_terraform(fixture_ws)}
    assert res["aws_instance.api"].value("instance_type") == "m5.2xlarge"
    assert res["aws_db_instance.main"].value("storage_encrypted") == "false"


def test_ast_inventory_and_routes(fixture_ws):
    m = analyse_python_module(fixture_ws, fixture_ws.path("shop/utils.py"))
    complexity = {f.name: f.complexity for f in m.functions}
    assert complexity["process_order"] >= 15
    routes, apps = discover_python_routes(fixture_ws, fixture_ws.path("shop/app.py"))
    assert apps == {"app": "flask"}
    paths = {(r.method, r.path): r for r in routes}
    assert ("POST", "/quote") in paths and paths[("GET", "/admin/orders")].requires_auth


def test_characterization_cases(fixture_ws):
    m = analyse_python_module(fixture_ws, fixture_ws.path("shop/pricing.py"))
    fn = next(f for f in m.functions if f.name == "apply_tax")
    cases = build_cases(fn)
    assert cases and all(len(c) == 2 for c in cases)
    assert any("'UK'" in c for c in cases)


def test_dump_adapter_reads_measured_spend(settings):
    a = DumpAwsAdapter(settings.fixtures_dir / "aws" / "orders-api", "orders-api")
    assert a.inventory() and not a.report.simulated and not a.report.errors
    cost = a.cost()
    assert cost.measured and sum(v for series in cost.by_service.values() for _, v in series) > 0


def test_missing_dump_reports_error(settings):
    from app.adapters.aws.factory import build_aws_adapter

    adapter = build_aws_adapter(settings, None)
    assert adapter.report.errors and adapter.inventory() == []


def test_anomaly_detection():
    series = {"svc": [(f"d{i}", 10.0 + (i % 3) * 0.5) for i in range(40)] + [("spike", 60.0)]}
    found = detect_anomalies(series)
    assert found and found[0]["date"] == "spike"
