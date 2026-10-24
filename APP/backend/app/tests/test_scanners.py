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


def _polyglot_repo(tmp_path):
    from app.adapters.repository.git_repo import RepoWorkspace

    files = {
        "pom.xml": "<project><dependencies>\n<dependency>\n<groupId>org.apache.logging.log4j</groupId>\n"
                   "<artifactId>log4j-core</artifactId>\n<version>2.14.1</version>\n</dependency>\n"
                   "</dependencies></project>\n",
        "app/build.gradle": "dependencies {\n  implementation 'com.fasterxml.jackson.core:jackson-databind:2.9.8'\n}\n",
        "Gemfile.lock": "GEM\n  specs:\n    rails (5.2.0)\n    nokogiri (1.10.0)\n",
        "Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"\n[dependencies]\nhyper = \"0.14.10\"\n",
        "api/Api.csproj": '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
                          "</ItemGroup></Project>\n",
        "svc/main.go": "package main\nimport \"crypto/tls\"\nfunc client() *tls.Config {\n"
                       "  return &tls.Config{InsecureSkipVerify: true}\n}\n"
                       "func grade(n int) string {\n if n > 90 { return \"A\" } else if n > 80 { return \"B\" }"
                       " else if n > 70 { return \"C\" }\n return \"F\"\n}\n",
        "src/Db.java": "class Db { void q(String id) throws Exception { stmt.executeQuery(\"SELECT * FROM t WHERE id=\""
                       " + id); } }\n",
    }
    for rel, content in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(content)
    return RepoWorkspace(tmp_path)


def test_polyglot_manifests_are_discovered_and_patchable(tmp_path):
    ws = _polyglot_repo(tmp_path)
    deps = {(d.ecosystem, d.name): d for d in discover_dependencies(ws)}
    assert ("Maven", "org.apache.logging.log4j:log4j-core") in deps
    assert ("Maven", "com.fasterxml.jackson.core:jackson-databind") in deps
    assert ("RubyGems", "rails") in deps and ("crates.io", "hyper") in deps and ("NuGet", "Newtonsoft.Json") in deps
    log4j = deps[("Maven", "org.apache.logging.log4j:log4j-core")]
    diff = upgrade_patch(ws, log4j, "2.17.1")
    assert diff and "+<version>2.17.1</version>" in diff


def test_polyglot_guardrails_and_complexity(tmp_path):
    from app.adapters.scanners.code_metrics import analyse_polyglot
    from app.agents.security_guardrails import CODE_RULES

    ws = _polyglot_repo(tmp_path)
    hits = {r.id for r in CODE_RULES for rel in ("svc/main.go", "src/Db.java")
            if rel.endswith(r.exts) and r.pattern.search(ws.read_text(rel))}
    assert {"go-tls-insecure", "java-sql-concat"} <= hits
    fns, sloc = analyse_polyglot(ws)
    assert "go" in sloc and any(f.name == "grade" and f.complexity >= 4 for f in fns)


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


def test_dependency_verification_separates_original_and_new_advisories(tmp_path):
    from types import SimpleNamespace

    from app.adapters.repository.git_repo import RepoWorkspace
    from app.models import Finding
    from app.services.remediation import _verify_dependency

    (tmp_path / "package.json").write_text('{"dependencies":{"semver":"7.3.5"}}')
    ws = RepoWorkspace(tmp_path)
    original = Advisory("GHSA-original", ["CVE-2024-0001"], "original", "high", None, [], [], None)
    unrelated = Advisory("GHSA-new", ["CVE-2025-0002"], "new", "medium", None, [], [], None)
    finding = Finding(target="package.json", evidence={"package": "semver", "ecosystem": "npm",
                                                         "advisories": [{"id": original.id,
                                                                         "aliases": original.aliases}]})
    checks: list[dict] = []
    assert not _verify_dependency(SimpleNamespace(osv=SimpleNamespace(query=lambda *_: [original])), ws,
                                  finding, checks)
    assert checks[1]["passed"] is False and checks[2]["passed"] is True
    checks.clear()
    assert not _verify_dependency(SimpleNamespace(osv=SimpleNamespace(query=lambda *_: [unrelated])), ws,
                                  finding, checks)
    assert checks[1]["passed"] is True and checks[2]["passed"] is False


def test_npm_remediation_updates_lockfile_without_resolving_unrelated_tree(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace

    import httpx

    from app.services.remediation import _sync_npm_lock

    wt = tmp_path / "worktree"
    wt.mkdir()
    (wt / "package.json").write_text('{"dependencies":{"semver":"^7.5.2"}}')
    lock = {"name": "test", "lockfileVersion": 1, "dependencies": {
        "semver": {"version": "7.3.5", "resolved": "https://registry/semver-7.3.5.tgz",
                   "integrity": "sha512-old", "requires": {"lru-cache": "^6.0.0"}},
        "lru-cache": {"version": "6.0.0", "resolved": "https://registry/lru-cache-6.0.0.tgz"}}}
    (wt / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n")

    def npm_metadata(url, timeout):
        assert url == "https://registry.npmjs.org/semver/7.5.2" and timeout == 30
        return httpx.Response(200, request=httpx.Request("GET", url),
                      json={"dist": {"tarball": "https://registry/semver-7.5.2.tgz",
                             "integrity": "sha512-new"},
                        "dependencies": {"lru-cache": "^6.0.0"}})

    monkeypatch.setattr(httpx, "get", npm_metadata)
    finding = SimpleNamespace(evidence={"package": "semver", "installed_version": "7.3.5"})
    update = _sync_npm_lock(wt, ["package.json"], finding)
    assert update and update[0] == "package-lock.json"
    assert '"version": "7.5.2"' in update[1]
    new_lock = json.loads((wt / "package-lock.json").read_text())
    assert new_lock["dependencies"]["semver"]["version"] == "7.5.2"
    assert new_lock["dependencies"]["semver"]["requires"] == {"lru-cache": "^6.0.0"}


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


def test_sandbox_retries_docker_after_transient_unavailable(monkeypatch):
    from types import SimpleNamespace

    import app.adapters.sandbox as sandbox_module

    sandbox = sandbox_module.DockerSandbox("node:22-slim", "1g", "1", 30)
    monkeypatch.setattr(sandbox_module.shutil, "which", lambda _name: "/usr/local/bin/docker")
    probe = iter([SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)])
    calls = []

    def run_probe(*_args, **_kwargs):
        calls.append(True)
        return next(probe)

    monkeypatch.setattr(sandbox_module.subprocess, "run", run_probe)

    assert sandbox.available() is False
    sandbox._availability_checked_at -= 6
    assert sandbox.available() is True
    assert len(calls) == 2


def test_anomaly_detection():
    series = {"svc": [(f"d{i}", 10.0 + (i % 3) * 0.5) for i in range(40)] + [("spike", 60.0)]}
    found = detect_anomalies(series)
    assert found and found[0]["date"] == "spike"


def test_polyglot_routes_and_blackbox_suite(tmp_path):
    import ast

    from app.adapters.repository.git_repo import RepoWorkspace
    from app.adapters.scanners.code_metrics import discover_polyglot_routes
    from app.agents.functional_test_agent import blackbox_suite

    files = {
        "src/main/java/OrderController.java": '@RestController\n@RequestMapping("/api/orders")\nclass C {\n'
                                              '  @GetMapping("/{id}")\n  Order get() {}\n'
                                              '  @PreAuthorize("hasRole(\'ADMIN\')")\n  @PostMapping("")\n'
                                              '  Order create() {}\n}\n',
        "cmd/server.go": 'func main() {\n r := gin.Default()\n r.GET("/health", h)\n r.POST("/items/:id", h)\n'
                         ' http.HandleFunc("/legacy", h)\n}\n',
        "config/routes.rb": "Rails.application.routes.draw do\n  get '/products', to: 'products#index'\nend\n",
    }
    for rel, content in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(content)
    routes = discover_polyglot_routes(RepoWorkspace(tmp_path))
    got = {(r.framework, r.method, r.path) for r in routes}
    assert ("spring", "GET", "/api/orders/{id}") in got and ("spring", "POST", "/api/orders/") in got
    assert ("go-http", "GET", "/health") in got and ("go-http", "POST", "/items/:id") in got
    assert ("go-http", "GET", "/legacy") in got and ("rails", "GET", "/products") in got
    assert any(r.requires_auth for r in routes if r.method == "POST" and r.framework == "spring")
    suite = blackbox_suite("spring", [r for r in routes if r.framework == "spring"])
    ast.parse(suite)
    assert "handles_unusual_path_params" in suite and "BASE_URL" in suite
