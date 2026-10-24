from __future__ import annotations

import threading
from pathlib import Path

import pytest

from app.adapters.repository.git_repo import RepoWorkspace
from app.adapters.scanners.js_refactor import (
    aggregation_refactor,
    fix_unused_requires,
    js_tokens,
    unused_require_edits,
    verify_js_refactor,
)
from app.agents.base import AgentContext
from app.agents.code_health_agent import CodeHealthAgent
from app.agents.security_guardrails import PolicyEngine

# Exact duplicated service pattern from the scanned OrderFlow JavaScript checkout.
SERVICE = """function calculateCarrier(records, options = {}) {
  const output = [];
  let total = 0;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    let value = Number(record.amount || record.price || 0);
    const quantity = Number(record.quantity || 1);
    const status = String(record.status || 'unknown');
    if (['cancelled', 'void', 'failed'].includes(status)) value *= 0;
    else if (['priority', 'gold', 'express'].includes(status)) value *= 0.92;
    if (quantity > Number(options.bulkThreshold || 25)) value *= 0.95;
    total += value * quantity;
    output.push({
      index,
      recordId: record.id === undefined ? index : record.id,
      domain: 'shipping',
      operation: 'carrier',
      value: Math.round(value * quantity * 100) / 100,
      status,
      processedAt: new Date().toISOString()
    });
  }
  return { items: output, total: Math.round(total * 100) / 100, count: records.length };
}

function summarizeCarrier(records) {
  // Similar aggregation logic intentionally repeated across modules.
  let count = 0;
  let amount = 0;
  const statuses = {};
  for (const record of records) {
    count += 1;
    amount += Number(record.amount || 0);
    const key = record.status || 'unknown';
    statuses[key] = (statuses[key] || 0) + 1;
  }
  return { count, amount: Math.round(amount * 100) / 100, statuses };
}
module.exports = { calculateCarrier, summarizeCarrier };
"""
MONEY = """function money(value) { return Math.round((Number(value) + Number.EPSILON) * 100) / 100; }
module.exports = { money };
"""


def sources() -> dict[str, str]:
    return {"src/services/shippingCarrier.js": SERVICE,
            "src/services/shippingDelivery.js": SERVICE.replace("Carrier", "Delivery"),
            "src/utils/money.js": MONEY}


def test_actual_aggregation_pattern_is_extracted_without_changing_calculations():
    before = sources()
    plan = aggregation_refactor(before)
    assert plan is not None
    assert len(plan.occurrences) == 2
    assert plan.helper_file == "src/utils/money.js"
    assert verify_js_refactor(before, plan.changes)
    for path in before.keys() - {plan.helper_file}:
        assert before[path].split("function summarize")[0] == plan.changes[path].split("function summarize")[0]
        assert "return require('../utils/money.js').summarizeRecords(records);" in plan.changes[path]
        assert before[path].split("module.exports")[1] == plan.changes[path].split("module.exports")[1]
    original_body = SERVICE.split("function summarizeCarrier(records) ", 1)[1].split("\nmodule.exports", 1)[0]
    shared_body = plan.changes[plan.helper_file].split("function summarizeRecords(records) ", 1)[1]
    shared_body = shared_body.split("\n\nmodule.exports", 1)[0]
    assert [t.value for t in js_tokens(original_body)] == [t.value for t in js_tokens(shared_body)]
    assert aggregation_refactor(plan.changes) is None


@pytest.mark.parametrize("before,after", [
    ("const unused = require('./effects');\n", "require('./effects');\n"),
    ("let unused = require('throws');\r\n", "require('throws');\r\n"),
    ("const unused = require('x');", "require('x');"),
])
def test_unused_binding_keeps_module_evaluation_and_line_endings(before, after):
    assert fix_unused_requires(before) == after
    assert verify_js_refactor({"a.js": before}, {"a.js": after})
    assert not verify_js_refactor({"a.js": before}, {"a.js": ""})


@pytest.mark.parametrize("text", [
    "/*\nconst unused = require('effect');\n*/\n",
    "const template = `\nconst unused = require('effect');\n`;\n",
    "const template = `prefix ${`nested`} suffix`;\nconst unused = require('effect');\n",
    "const regex = /require\\('x'\\)/;\nconst unused = require('effect');\n",
    "const { unused } = require('getter');\n",
    "const [unused] = require('iterator');\n",
    "const { unused = run() } = require('defaults');\n",
    "var unused = require('global-property');\n",
    "import unused from 'missing-export';\n",
    "import { absent } from 'missing-export';\n",
    "import type { Thing } from 'types';\n",
    "import 'effect';\nrequire('effect');\n",
    "const unused = require('effect');\n// unused is documented\n",
    "const unused = require('effect');\neval('un' + 'used');\n",
    "const unused = require('effect');\nwith (obj) { run(); }\n",
    "export\nconst unused = require('effect');\n",
    "const unused = require('effect')\n",
    "const unused = require('effect'); run();\n",
    "function f() {\nconst unused = require('effect');\n}\n",
    "const used = require('effect');\nused.run();\n",
    "const require = require('effect');\n",
    "const \\u0075nused = require('effect');\n",
])
def test_import_safety_edge_cases_are_left_untouched(text):
    assert unused_require_edits(text) == []
    assert fix_unused_requires(text) == text


@pytest.mark.parametrize("mutation", [
    lambda text: text.replace("record.amount || 0", "record.amount || fallback"),
    lambda text: text.replace("amount += Number", "amount += parseFloat"),
    lambda text: text.replace("amount * 100", "amount * 1000"),
    lambda text: text.replace("const statuses = {};", "const statuses = Object.create(null);"),
    lambda text: "const Number = customNumber;\n" + text,
    lambda text: "'use strict';\n" + text,
    lambda text: "/*\n" + text + "\n*/",
    lambda text: "const template = `\n" + text + "\n`;",
    lambda text: text.replace("function summarizeCarrier", "async function summarizeCarrier"),
])
def test_nonidentical_or_scope_sensitive_aggregation_is_not_extracted(mutation):
    before = sources()
    before["src/services/shippingCarrier.js"] = mutation(SERVICE)
    assert aggregation_refactor(before) is None


@pytest.mark.parametrize("utility", [
    "const local = require('side-effects');\n" + MONEY,
    "initialize();\n" + MONEY,
    "const Number = custom;\n" + MONEY,
    MONEY.replace("function money", "function Math"),
    MONEY.replace("module.exports = { money };", "module.exports = { get money() { return load(); } };"),
    MONEY + "module.exports.summarizeRecords = override;\n",
    MONEY.replace("function money", "function summarizeRecords"),
])
def test_helper_must_be_existing_initialization_free_and_collision_free(utility):
    before = sources()
    before["src/utils/money.js"] = utility
    assert aggregation_refactor(before) is None
    before.pop("src/utils/money.js")
    assert aggregation_refactor(before) is None


def test_replay_verification_rejects_unrelated_edits_and_missing_files():
    before = sources()
    plan = aggregation_refactor(before)
    assert plan is not None
    after = dict(plan.changes)
    after["src/utils/money.js"] = after["src/utils/money.js"].replace("amount * 100", "amount * 101")
    assert not verify_js_refactor(before, after)
    after = dict(plan.changes)
    after.pop("src/utils/money.js")
    assert not verify_js_refactor(before, after)
    assert not verify_js_refactor({}, {})
    assert not verify_js_refactor(before, before)


def test_aggregation_is_crlf_preserving_and_policy_bounded():
    before = {f"src/services/service{i:02}.js": SERVICE.replace("Carrier", f"Service{i}")
              for i in range(30)}
    before["src/utils/money.js"] = MONEY
    before = {p: t.replace("\n", "\r\n") for p, t in before.items()}
    plan = aggregation_refactor(before)
    assert plan is not None and len(plan.changes) == 20
    assert all("\n" not in text.replace("\r\n", "") for text in plan.changes.values())
    assert verify_js_refactor({p: before[p] for p in plan.changes}, plan.changes)


def test_code_health_proposes_real_duplication_patch_that_passes_policy(tmp_path, monkeypatch):
    before = sources()
    for path, text in before.items():
        dest = tmp_path / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    # Avoid even local git history access: static generation needs only source data.
    monkeypatch.setattr("app.agents.code_health_agent.churn", lambda ws: {})
    ws = RepoWorkspace(tmp_path)
    agent = CodeHealthAgent()
    ctx = AgentContext(scan_id="s", project={}, workspace=ws, options={},
                       tools={"repo.read": ws, "static.ruff": True, "static.radon": True},
                       allowed_tools=agent.allowed_tools, emit=lambda *a, **kw: None,
                       cancel_event=threading.Event())
    result = agent.run(ctx)
    finding = next(f for f in result.findings if f.rule_id == "health:duplicate-aggregation")
    assert finding.proposal is not None
    assert result.metrics["dead_imports"] == 0
    assert result.metrics["js_aggregation_modules_refactored"] == 2
    assert PolicyEngine(ws).validate(finding.proposal)["passed"]
    assert {p: ws.read_text(p) for p in before} == before


def test_available_real_checkout_generates_reviewable_patch(monkeypatch):
    root = Path(__file__).resolve().parents[3] / "data" / "workspaces"
    # Local checkouts are not committed fixtures; CI validates the copied pattern above.
    checkouts = sorted(root.glob("*/*/repo"))
    if not checkouts:
        pytest.skip("No local scanned checkout available")
    monkeypatch.setattr("app.agents.code_health_agent.churn", lambda ws: {})
    for checkout in checkouts:
        ws = RepoWorkspace(checkout)
        if not ws.exists("src/services/shippingCarrier.js"):
            continue
        before = {ws.rel(p): ws.read_text(p) for p in ws.iter_files({".js"})}
        plan = aggregation_refactor(before)
        assert plan is not None
        assert len(plan.occurrences) == 19
        assert verify_js_refactor({p: before[p] for p in plan.changes}, plan.changes)
        return
    pytest.skip("OrderFlow checkout not available")
