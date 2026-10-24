"""Agent 2 — Unit Test & Coverage Agent.

1. Inventories source functions (AST) and existing tests.
2. Measures baseline coverage by running the existing suite in the Docker sandbox (if permitted/available).
3. Generates focused tests for uncovered, deterministic functions:
   - with the local LLM when available (validated + executed before being proposed), otherwise
   - as *characterization tests*: the sandbox records the real behaviour of pure functions for representative
     inputs (calling twice to reject non-determinism) and tests pin that behaviour with exact assertions.
4. Re-measures coverage with the generated tests and proposes only tests that pass.
"""

from __future__ import annotations

import ast
import itertools
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from app.adapters.repository.git_repo import RepoWorkspace
from app.adapters.sandbox import DockerSandbox, SandboxResult
from app.adapters.scanners.aws_mocks import MOCK_DIR, AwsMockPlan, mock_files, plan_aws_mocks
from app.adapters.scanners.code_metrics import FunctionInfo, analyse_python_module, is_test_path, module_name_for
from app.adapters.scanners.languages import (
    LANGUAGES,
    Symbol,
    inventory_symbols,
    profile_repository,
    test_path_for,
)
from app.adapters.scanners.manifests import unified_diff
from app.adapters.scanners.test_scaffold import render_unit_scaffold
from app.agents.base import AgentContext, BaseAgent
from app.agents.security_guardrails import scan_generated_code
from app.schemas.agents import AgentResult, ArtifactDraft, FindingDraft, ProposalDraft, TestRunDraft
from app.services.llm import LLMService, wrap_untrusted

SIDE_EFFECT_NAME = re.compile(r"^(save|write|delete|remove|send|post|put|upload|run|exec|open|connect|create|update|"
                              r"drop|kill|start|stop|main|init|setup|install|download|fetch|request|login|logout|"
                              r"print|log|serve|listen|migrate|seed|commit|push|publish|emit|notify)")
SIDE_EFFECT_SRC = re.compile(r"\b(open\(|requests\.|httpx\.|urllib|subprocess|os\.system|os\.remove|shutil\.|socket|"
                             r"input\(|random\.|time\.time|datetime\.now|uuid|sqlite3|session\.|cursor|\.execute\(|"
                             r"print\(|logging\.|threading|asyncio|global )")
# Web-framework context access: these only work inside a live request/app context, so calling the function directly
# would pin an environmental error rather than real behaviour.
REQUEST_CONTEXT_SRC = re.compile(r"\b(request\.|flask\.request|current_app|url_for\(|jsonify\(|render_template|"
                                 r"redirect\(|make_response\(|send_file\(|abort\(|flash\(|g\.[a-z_]|Depends\(|"
                                 r"HTTPException|self\.get_argument|rest_framework)")
INT_NAMES = {"n", "num", "count", "i", "j", "k", "x", "y", "size", "limit", "index", "idx", "number", "age", "year",
             "times", "length", "width", "height", "depth", "level", "a", "b"}
STR_NAMES = {"name", "text", "s", "string", "word", "msg", "message", "title", "key", "label", "value", "slug",
             "email", "username", "query", "prefix", "suffix", "sep", "char", "token", "line", "sentence"}
LIST_NAMES = {"items", "values", "lst", "data", "numbers", "nums", "elements", "words", "arr", "array", "seq"}

# Decorators that only *register* a function (web routes, CLI commands, task queues) and return it unchanged, so the
# undecorated callable is still importable and directly testable. Handlers that actually need a request context are
# filtered out separately by SIDE_EFFECT_SRC (`request.`, `session.`, `g.`, …).
TRANSPARENT_DECORATOR = re.compile(
    r"^(staticmethod|functools\.lru_cache|lru_cache|cache|functools\.cache)\b|"
    r"^[\w.]*(app|application|router|api|bp|blueprint|mod|server|cli|celery|dramatiq|huey)[\w.]*\."
    r"(route|get|post|put|patch|delete|head|options|api_route|websocket|command|group|task|shared_task|job)\b",
    re.IGNORECASE)

# Suffix heuristics for unannotated parameters, applied after the exact-name lookups above.
NAME_SUFFIX_KINDS: tuple[tuple[str, str], ...] = (
    ("_id", "int"), ("_count", "int"), ("_num", "int"), ("_number", "int"), ("_index", "int"), ("_idx", "int"),
    ("_size", "int"), ("_len", "int"), ("_length", "int"), ("_total", "int"), ("_offset", "int"), ("_limit", "int"),
    ("_name", "str"), ("_text", "str"), ("_str", "str"), ("_msg", "str"), ("_message", "str"), ("_url", "str"),
    ("_path", "str"), ("_key", "str"), ("_slug", "str"), ("_email", "str"), ("_title", "str"), ("_code", "str"),
    ("_items", "list"), ("_list", "list"), ("_values", "list"), ("_names", "list"), ("_rows", "list"),
    ("_map", "dict"), ("_dict", "dict"), ("_config", "dict"), ("_options", "dict"), ("_params", "dict"),
    ("_flag", "bool"), ("_enabled", "bool"), ("is_", "bool"), ("has_", "bool"),
)

SAMPLES: dict[str, list[Any]] = {
    "int": [0, 1, -3, 12], "float": [0.0, 2.5, -1.25], "str": ["", "abc", "Hello World"], "bool": [True, False],
    "list": [[], [3, 1, 2]], "dict": [{}, {"a": 1, "b": 2}], "tuple": [(), (1, 2)], "set": [set(), {1, 2}],
    "None": [None],
}

HARNESS = r'''
import importlib, json, signal, sys, traceback
JOBS = json.loads(open("/work/.sf_jobs.json").read())
SIMPLE = (int, float, str, bool, type(None))
def simple(v, depth=0):
    if isinstance(v, SIMPLE):
        return not (isinstance(v, str) and len(v) > 300)
    if depth < 2 and isinstance(v, (list, tuple, set, frozenset)) and len(v) <= 20:
        return all(simple(x, depth + 1) for x in v)
    if depth < 2 and isinstance(v, dict) and len(v) <= 20:
        return all(isinstance(k, SIMPLE) and simple(x, depth + 1) for k, x in v.items())
    return False
class TO(Exception): pass
def alarm(*_): raise TO()
signal.signal(signal.SIGALRM, alarm)
out = []
for job in JOBS:
    rec = {"id": job["id"], "cases": [], "error": None}
    try:
        signal.alarm(5)
        mod = importlib.import_module(job["module"])
        fn = getattr(mod, job["function"])
        signal.alarm(0)
    except BaseException as e:
        signal.alarm(0)
        rec["error"] = "import: " + type(e).__name__
        out.append(rec); continue
    for args in job["cases"]:
        res = []
        for _ in range(2):
            try:
                signal.alarm(2)
                v = fn(*[eval(a, {}) for a in args])
                signal.alarm(0)
                res.append(("value", repr(v), simple(v), type(v).__name__))
            except TO:
                res.append(("timeout", None, False, None))
            except BaseException as e:
                signal.alarm(0)
                res.append(("raises", type(e).__name__, type(e).__module__ == "builtins", None))
        rec["cases"].append({"args": args, "first": res[0], "stable": res[0] == res[1]})
    out.append(rec)
open("/work/.sf_harness.json", "w").write(json.dumps(out))
'''


def _kind(annotation: str | None, name: str) -> str | None:
    if annotation:
        a = annotation.replace("typing.", "").replace(" ", "")
        if a.startswith(("Optional[", "Union[")) or "|None" in a:
            inner = re.sub(r"^(Optional|Union)\[|\]$|\|None", "", a).split(",")[0]
            return _kind(inner, name)
        base = re.split(r"[\[|]", a)[0].lower()
        return {"int": "int", "float": "float", "str": "str", "bool": "bool", "list": "list", "sequence": "list",
                "iterable": "list", "dict": "dict", "mapping": "dict", "tuple": "tuple", "set": "set",
                "none": "None"}.get(base)
    lname = name.lower()
    if lname in INT_NAMES:
        return "int"
    if lname in STR_NAMES:
        return "str"
    if lname in LIST_NAMES:
        return "list"
    for affix, kind in NAME_SUFFIX_KINDS:
        if (lname.startswith(affix) if affix.endswith("_") else lname.endswith(affix)):
            return kind
    return None


def build_cases(fn: FunctionInfo, limit: int = 6) -> list[list[str]] | None:
    per_arg: list[list[str]] = []
    for a in fn.args:
        if a["name"].startswith("*"):
            continue
        options: list[str] = []
        if a.get("default") is not None:
            try:
                ast.literal_eval(a["default"])
                options.append(a["default"])
            except (ValueError, SyntaxError):
                if a.get("kwonly"):
                    continue
        kind = _kind(a.get("annotation"), a["name"])
        if kind:
            options += [repr(v) for v in SAMPLES[kind]]
        if not options:
            return None
        per_arg.append(list(dict.fromkeys(options))[:4])
    if len(per_arg) > 4:
        return None
    combos = list(itertools.islice(itertools.product(*per_arg), 64)) if per_arg else [()]
    step = max(1, len(combos) // limit)
    return [list(c) for c in combos[::step][:limit]]


GENERATED_DIR = "skyforge_tests"  # Own top-level test dir: never inherits the repo's test package/conftest.


def generated_test_path(module: str, suffix: str = "") -> str:
    return f"{GENERATED_DIR}/test_{_safe_ident(module)}{('_' + _safe_ident(suffix)) if suffix else ''}.py"


def module_mutable_globals(source: str) -> set[str]:
    """Names bound at module scope to a mutable literal (list/dict/set).

    A function that reads or writes one of these is not safe to pin with a characterization test: any other test in
    the same process can mutate the global first and the expectation becomes order-dependent.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    names: set[str] = set()
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None:
            continue
        mutable = isinstance(value, ast.List | ast.Dict | ast.Set | ast.ListComp | ast.DictComp | ast.SetComp) or (
            isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
            and value.func.id in ("list", "dict", "set", "defaultdict", "deque", "Counter", "OrderedDict"))
        if mutable:
            names |= {t.id for t in targets if isinstance(t, ast.Name)}
    return names


def is_route_handler(fn: FunctionInfo) -> bool:
    """True when the function is only *registered* by its decorator (Flask/FastAPI route, CLI command, task)."""
    return any(TRANSPARENT_DECORATOR.match(d) and "." in d.split("(")[0] for d in fn.decorators)


def _safe_ident(s: str) -> str:
    return re.sub(r"[^0-9a-zA-Z_]", "_", s)[:60]


def line_ranges(lines: list[int], max_ranges: int = 6) -> str:
    """Collapse sorted line numbers into human-readable ranges, e.g. '12-18, 24, 31-33'."""
    if not lines:
        return ""
    ordered = sorted(set(lines))
    ranges: list[tuple[int, int]] = [(ordered[0], ordered[0])]
    for n in ordered[1:]:
        if n == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], n)
        else:
            ranges.append((n, n))
    shown = [f"{a}-{b}" if a != b else str(a) for a, b in ranges[:max_ranges]]
    if len(ranges) > max_ranges:
        shown.append(f"+{len(ranges) - max_ranges} more")
    return ", ".join(shown)


@dataclass
class CoverageGap:
    """An uncovered region of a function, with the data needed to prioritise writing a test for it."""

    function: FunctionInfo
    missing: list[int]
    statements: int

    @property
    def missing_count(self) -> int:
        return len(self.missing)

    @property
    def score(self) -> float:
        """Priority = uncovered lines weighted by branching complexity (risk × reward)."""
        return self.missing_count * (1 + self.function.complexity / 5)


def function_gaps(functions: list[FunctionInfo], missing: list[int]) -> list[CoverageGap]:
    missing_set = set(missing)
    gaps: list[CoverageGap] = []
    for f in functions:
        span = range(f.line, f.end_line + 1)
        hit = sorted(n for n in span if n in missing_set)
        if hit:
            gaps.append(CoverageGap(function=f, missing=hit, statements=len(span)))
    gaps.sort(key=lambda g: -g.score)
    return gaps


def _suggest_cases(f: FunctionInfo) -> list[str]:
    """Suggest the input classes worth covering, derived from the signature and body shape."""
    hints: list[str] = []
    for a in f.args:
        if a["name"].startswith(("*", "self", "cls")):
            continue
        kind = _kind(a.get("annotation"), a["name"])
        if kind in ("int", "float"):
            hints.append(f"`{a['name']}` = 0, a negative value and a large value")
        elif kind == "str":
            hints.append(f"`{a['name']}` = empty string, typical text and text with unexpected characters")
        elif kind in ("list", "dict", "tuple", "set"):
            hints.append(f"`{a['name']}` = empty, single-element and multi-element {kind}")
        elif a.get("default") in ("None", None) and a.get("annotation") and "None" in str(a.get("annotation")):
            hints.append(f"`{a['name']}` = None and a populated value")
        else:
            hints.append(f"`{a['name']}` = a representative value and one the function should reject")
    if f.returns and f.returns.replace(" ", "").endswith("|None"):
        hints.append("both branches of the optional return: a found value and None")
    if f.is_async:
        hints.append("await the coroutine with `pytest.mark.asyncio` (or `anyio`) and assert the resolved value")
    if f.complexity >= 5:
        hints.append(f"one case per branch — complexity {f.complexity} implies ~{f.complexity} independent paths")
    if len(hints) >= 3:
        hints.append("drive them from a single `@pytest.mark.parametrize` table so adding a case costs one line")
    if not hints:
        hints.append("a happy-path case plus one boundary/error case")
    return hints[:5]


def module_suggestions(file: str, gaps: list[CoverageGap], cov: float | None, statements: int | None,
                       missing_total: int, measured: bool = True) -> str:
    """Build the actionable 'where to improve coverage' recommendation for one module."""
    if not gaps:
        return ("Add focused tests for the highest-complexity untested functions in this module first, starting with "
                "the public API surface.")
    lines = [f"Where to improve coverage in {file} — work top-down, the list is ordered by uncovered lines × "
             f"complexity:"]
    for i, g in enumerate(gaps[:5], 1):
        f = g.function
        gain = f" (~+{100 * g.missing_count / statements:.0f} pts for this file)" if measured and statements else ""
        lines.append(f"{i}. `{f.qualname}` (line {f.line}, complexity {f.complexity}) — {g.missing_count} uncovered "
                     f"line(s) at {line_ranges(g.missing)}{gain}. Cover: " + "; ".join(_suggest_cases(f)) + ".")
    if len(gaps) > 5:
        lines.append(f"…and {len(gaps) - 5} further function(s) with uncovered lines in this module.")
    covered_by_plan = sum(g.missing_count for g in gaps[:5])
    if measured and statements and cov is not None:
        target = min(100.0, cov + 100 * covered_by_plan / statements)
        lines.append(f"Covering just these takes {file} from {cov:.0f}% to roughly {target:.0f}%.")
    elif missing_total:
        lines.append(f"Covering just these closes {covered_by_plan} of {missing_total} uncovered line(s). Coverage "
                     f"was not measured for this scan, so these are static estimates.")
    return "\n".join(lines)


def _drop_tests(code: str, names: set[str]) -> str | None:
    """Remove test functions/methods with the given names, preserving the rest of the source verbatim."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in names:
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            spans.append((start, node.end_lineno or node.lineno))
    if not spans:
        return None
    lines = code.splitlines()
    keep = [ln for i, ln in enumerate(lines, 1) if not any(a <= i <= b for a, b in spans)]
    out = "\n".join(keep) + "\n"
    try:
        ast.parse(out)
    except SyntaxError:
        return None
    return out


class UnitTestAgent(BaseAgent):
    id = "unit_test"
    name = "Unit Test & Coverage"
    code = "Unit Test & Coverage"
    description = ("Measures coverage in a sandbox, then generates validated unit tests for the uncovered logic "
                   "in any supported language.")
    allowed_tools = frozenset({"repo.read", "static.radon", "sandbox.execute", "llm.generate", "terraform.parse"})

    def run(self, ctx: AgentContext) -> AgentResult:
        ws: RepoWorkspace = ctx.tool("repo.read")
        result = AgentResult(agent_id="unit_test", tools_used=["ast", "radon"])
        profile = profile_repository(ws)
        ctx.log("Repository languages: " + (", ".join(f"{lang} ({n} file(s))" for lang, n in profile.files.items())
                                            or "none detected"), data={"profile": profile.as_dict()})
        py_files = [p for p in ws.iter_files({".py"}) if not ws.rel(p).startswith(("docs/", "examples/"))]
        sources = [p for p in py_files if not is_test_path(ws.rel(p)) and p.name not in ("setup.py", "conftest.py")
                   and "migrations" not in ws.rel(p)]
        tests = [p for p in py_files if is_test_path(ws.rel(p))]
        ctx.progress(0.08, "Language profile complete")

        # AWS mocks are derived from the repo's own Terraform; with no Terraform this step is skipped entirely.
        aws_plan, aws_artifacts = self._aws_mocks(ctx, ws, result)

        # Every non-Python language gets an inventory + idiomatic, explicitly-pending unit scaffolds.
        polyglot = self._polyglot(ctx, ws, profile, result)
        ctx.progress(0.15, "Polyglot inventory complete")
        js_sources = sum(profile.files.get(language, 0) for language in ("javascript", "typescript"))
        js_baseline = self._javascript_baseline(ctx, ws, result) if js_sources else None

        if not sources:
            if js_baseline is None:
                result.notes.append("No Python or JavaScript/TypeScript sources available for coverage measurement.")
            result.metrics = {"source_files": js_sources, "test_files": sum(profile.test_files.values()),
                              "languages": profile.files, "scaffolded_languages": polyglot,
                              "coverage_before": js_baseline.coverage_percent if js_baseline else None,
                              "coverage_after": None,
                              "sandbox_executed": bool(js_baseline and js_baseline.exit_code is not None),
                              "aws_mock_resources": len(aws_plan.resources) if aws_plan else 0,
                              "aws_mock_files": len(aws_artifacts)}
            ctx.progress(1.0, "Unit test analysis complete")
            return result

        modules = [analyse_python_module(ws, p) for p in sources]
        functions = [f for m in modules for f in m.functions]
        test_text = "\n".join(ws.read_text(p) for p in tests)
        referenced = {f.name for f in functions if re.search(rf"\b{re.escape(f.name)}\b", test_text)}
        ctx.progress(0.2, "Source inventory complete")

        sandbox: DockerSandbox | None = ctx.tool("sandbox.execute") if ctx.has_tool("sandbox.execute") else None
        execute = bool(ctx.options.get("execute_tests", True) and sandbox and sandbox.available())
        baseline: SandboxResult | None = None
        after: SandboxResult | None = None
        generated: dict[str, str] = {}
        gen_meta: dict[str, dict] = {}

        if not execute:
            reason = ("Test execution disabled for this scan" if not ctx.options.get("execute_tests", True)
                      else "Docker sandbox unavailable — tests not executed (fail-closed)")
            ctx.log(reason, level="warning")
            result.test_runs.append(TestRunDraft(kind="unit", status="not_executed", details={"reason": reason}))
            if ctx.options.get("generate_tests", True) and ctx.has_tool("llm.generate"):
                generated, gen_meta = self._llm_tests(ctx, ws, functions, referenced, set(), None)
        else:
            assert sandbox is not None
            with sandbox.session(ws.root) as session:
                ctx.log("Installing project dependencies inside the sandbox (network enabled for install only)")
                err = session.install()
                ctx.check_cancelled()
                if err:
                    ctx.log(f"Sandbox install failed: {err.reason}", level="error")
                    result.status = "partial"
                    result.test_runs.append(TestRunDraft(kind="unit", status="error",
                                                         details={"reason": err.reason, "log": err.log_tail[-1500:]}))
                else:
                    ctx.progress(0.35, "Running existing test suite (network disabled)")
                    test_targets = sorted({ws.rel(p).split("/")[0] if "/" in ws.rel(p) else ws.rel(p)
                                           for p in tests})
                    baseline = session.pytest(test_targets or None) if tests else SandboxResult(
                        status="not_executed", coverage_percent=0.0, reason="Repository has no Python tests")
                    ctx.log(f"Baseline: {baseline.status}, {baseline.passed}/{baseline.total} passed, coverage "
                            f"{baseline.coverage_percent if baseline.coverage_percent is not None else 'n/a'}%")
                    result.test_runs.append(self._run_draft(baseline, "Baseline (existing tests)", None))
                    ctx.check_cancelled()
                    uncovered = self._uncovered(functions, baseline)
                    if ctx.options.get("generate_tests", True):
                        ctx.progress(0.5, "Generating tests for uncovered functions")
                        if ctx.has_tool("llm.generate") and ctx.options.get("use_llm", True) and \
                                ctx.tools["llm.generate"] is not None and ctx.tools["llm.generate"].usable:
                            generated, gen_meta = self._llm_tests(ctx, ws, functions, referenced, uncovered, session)
                        done = {m["function"] for m in gen_meta.values() if "function" in m}
                        more, more_meta = self._characterize(ctx, functions, referenced, uncovered, session, done)
                        generated.update(more)
                        gen_meta.update(more_meta)
                    if generated:
                        for rel, content in generated.items():
                            session.write_file(rel, content)
                        ctx.progress(0.8, "Re-running suite with generated tests")
                        all_targets = sorted(set((test_targets or []) + list(generated)))
                        after = session.pytest(all_targets)
                        result.test_runs.append(self._run_draft(after, "With SkyForge-generated tests",
                                                                baseline.coverage_percent))
                        ctx.log(f"After generation: {after.passed}/{after.total} passed, coverage "
                                f"{after.coverage_percent}%")

        # ---- findings ----
        cov_files = baseline.coverage_files if baseline else {}
        by_module: dict[str, list[FunctionInfo]] = defaultdict(list)
        for f in functions:
            by_module[f.file].append(f)
        produced = 0
        roadmap: list[dict[str, Any]] = []
        for m in modules:
            fns = by_module.get(m.file, [])
            if not fns:
                continue
            cov = cov_files.get(m.file)
            untested = [f for f in fns if f.name not in referenced and not f.name.startswith("_")]
            measured_low = cov is not None and cov < 60
            if not (measured_low or (cov is None and untested)):
                continue
            risky = sorted(untested or fns, key=lambda f: -f.complexity)[:8]
            if baseline and cov is not None:
                measured_cov = True
                missing = baseline.missing_lines.get(m.file, [])
                statements = baseline.statements.get(m.file) or m.sloc or None
                missing_total = baseline.missing_counts.get(m.file, len(missing))
                gaps = function_gaps(fns, missing)
            else:
                # No measured coverage: treat every untested public function as entirely uncovered.
                measured_cov = False
                statements = m.sloc or None
                gaps = sorted((CoverageGap(function=f, missing=list(range(f.line, f.end_line + 1)),
                                           statements=f.end_line - f.line + 1) for f in untested),
                              key=lambda g: -g.score)
                missing_total = sum(g.missing_count for g in gaps)
            suggestions = module_suggestions(m.file, gaps, cov, statements, missing_total, measured_cov)
            if gaps:
                roadmap.append({"file": m.file, "coverage_percent": cov, "uncovered_lines": missing_total,
                                "score": round(sum(g.score for g in gaps), 1),
                                "start_with": [{"function": g.function.qualname, "line": g.function.line,
                                                "uncovered_lines": g.missing_count,
                                                "complexity": g.function.complexity} for g in gaps[:3]]})
            sev = "high" if any(f.complexity >= 10 for f in risky) and (cov or 0) < 30 else (
                "medium" if (cov or 0) < 40 else "low")
            gen_for_module = {rel: c for rel, c in generated.items() if gen_meta.get(rel, {}).get("module") == m.file}
            proposal = None
            if gen_for_module:
                diff = "".join(unified_diff(rel, "", content).replace(f"--- a/{rel}", "--- /dev/null")
                               for rel, content in gen_for_module.items())
                n_tests = sum(gen_meta[r]["tests"] for r in gen_for_module)
                proposal = ProposalDraft(
                    kind="test_addition", title=f"Add {n_tests} generated test(s) for {m.file}",
                    summary=(" + ".join(sorted({gen_meta[r]["strategy"] for r in gen_for_module})) + " tests. "
                             + ("Executed in sandbox: all proposed tests passed." if execute and after else
                                "Not executed — review carefully before merging.")),
                    diff=diff, files=list(gen_for_module))
            result.findings.append(FindingDraft(
                rule_id="coverage:module", category="coverage", severity=sev,  # type: ignore[arg-type]
                title=(f"{m.file} has {cov:.0f}% line coverage" if cov is not None else
                       f"{m.file}: {len(untested)} public function(s) without tests"),
                description=("Untested logic: " + ", ".join(f"{f.qualname} (CC {f.complexity})" for f in risky)),
                target=m.file, location={"line": risky[0].line if risky else 1},
                evidence={"coverage_percent": cov, "measured": cov is not None,
                          "missing_lines": (baseline.missing_lines.get(m.file, [])[:60] if baseline else []),
                          "missing_line_ranges": line_ranges([n for g in gaps for n in g.missing], max_ranges=12),
                          "uncovered_lines": missing_total, "statements": statements,
                          "coverage_targets": [{"function": g.function.qualname, "line": g.function.line,
                                                "end_line": g.function.end_line, "complexity": g.function.complexity,
                                                "uncovered_lines": g.missing_count,
                                                "missing_line_ranges": line_ranges(g.missing),
                                                "estimated_file_coverage_gain_pts": (
                                                    round(100 * g.missing_count / statements, 1)
                                                    if measured_cov and statements else None)} for g in gaps[:8]],
                          "untested_functions": [{"name": f.qualname, "line": f.line, "complexity": f.complexity}
                                                 for f in risky]},
                recommendation=suggestions,
                confidence="high" if cov is not None else "medium",
                data_source="measured" if cov is not None else "estimated",
                fingerprint_key=f"coverage|{m.file}", proposal=proposal))
            produced += 1
            if produced >= 40:
                break

        if roadmap:
            result.findings.append(self._roadmap_finding(roadmap, baseline, after))

        for rel, content in generated.items():
            result.artifacts.append(ArtifactDraft(kind="test_file", name=_safe_ident(rel.replace("/", "_"))[:150]
                                                  + ".py", content=content, media_type="text/x-python"))
        total_fns = len(functions)
        result.metrics = {
            "source_files": len(sources) + js_sources, "test_files": sum(profile.test_files.values()), "functions": total_fns,
            "functions_referenced_by_tests": len(referenced),
            "coverage_before": self._coverage(baseline, js_baseline),
            "coverage_after": self._coverage(after, js_baseline) if after else None,
            "tests_generated": sum(m["tests"] for m in gen_meta.values()),
            "sandbox_executed": execute,
            "modules_needing_coverage": len(roadmap),
            "languages": profile.files,
            "test_files_by_language": profile.test_files,
            "scaffolded_languages": polyglot,
            "untested_languages": profile.untested(),
            "aws_mock_resources": len(aws_plan.resources) if aws_plan else 0,
            "aws_mock_services": aws_plan.services if aws_plan else [],
            "aws_mock_files": len(aws_artifacts),
        }
        ctx.progress(1.0, "Unit test analysis complete")
        return result

    @staticmethod
    def _coverage(*runs: SandboxResult | None) -> float | None:
        measured = [r for r in runs if r is not None and r.coverage_percent is not None]
        if not measured:
            return None
        if len(measured) == 1:
            return measured[0].coverage_percent
        totals = [sum(r.statements.values()) for r in measured]
        if any(total <= 0 for total in totals):
            return None  # Combining languages requires actual line counts, not an unweighted mean.
        return round(sum((r.coverage_percent or 0) * total for r, total in zip(measured, totals, strict=True))
                     / sum(totals), 1)

    def _javascript_baseline(self, ctx: AgentContext, ws: RepoWorkspace, result: AgentResult) -> SandboxResult:
        sandbox = ctx.tool("sandbox.execute") if ctx.has_tool("sandbox.execute") else None
        if not ctx.options.get("execute_tests", True):
            baseline = SandboxResult(status="not_executed", framework="javascript",
                                     reason="Test execution disabled for this scan")
        elif sandbox is None:
            baseline = SandboxResult(status="not_executed", framework="javascript",
                                     reason="Docker sandbox unavailable; JavaScript tests not executed")
        else:
            ctx.log("Measuring JavaScript/TypeScript coverage inside the Docker sandbox")
            baseline = sandbox.run_javascript_tests(ws.root)
        ctx.check_cancelled()
        result.test_runs.append(self._run_draft(baseline, "JavaScript baseline (existing tests)", None))
        if baseline.reason:
            result.notes.append(baseline.reason)
            ctx.log(baseline.reason, level="warning")
        if baseline.status == "error":
            result.status = "partial"
        return baseline

    # ---------------------------------------------------------------- AWS mocks from Terraform
    def _aws_mocks(self, ctx: AgentContext, ws: RepoWorkspace,
                   result: AgentResult) -> tuple[AwsMockPlan | None, dict[str, str]]:
        """Derive moto fixtures from the repository's Terraform. Returns (plan, files); both empty when skipped."""
        if not ctx.has_tool("terraform.parse"):
            return None, {}
        try:
            resources = ctx.tool("terraform.parse")(ws)
        except Exception as exc:  # noqa: BLE001 - never fail a scan because HCL could not be parsed
            ctx.log(f"Terraform parse failed ({type(exc).__name__}) — skipping AWS mock generation", level="warning")
            return None, {}
        if not resources:
            ctx.log("No Terraform in this repository — skipping AWS mock generation")
            return None, {}
        region = ((ctx.project.get("aws") or {}).get("regions") or [None])[0]
        plan = plan_aws_mocks(resources, region=region)
        if not plan:
            ctx.log(f"Terraform declares {len(resources)} resource(s) but none map to a mockable AWS service "
                    f"({', '.join(sorted(plan.skipped_types))}) — skipping AWS mock generation")
            return plan, {}
        files = mock_files(plan)
        unsafe = [rel for rel, content in files.items() if rel.endswith(".py") and scan_generated_code(content)]
        for rel in unsafe:
            files.pop(rel)
        if unsafe or not files:
            ctx.log("Generated AWS mocks failed the guardrail scan — discarded", level="warning")
            return plan, {}
        ctx.log(f"Generated mock AWS data for {len(plan.resources)} Terraform resource(s) across "
                f"{len(plan.services)} service(s): {', '.join(plan.services)}")
        for rel, content in files.items():
            result.artifacts.append(ArtifactDraft(
                kind="test_file", name=rel.split("/")[-1], content=content,
                media_type="application/json" if rel.endswith(".json") else "text/x-python"))
        diff = "".join(unified_diff(rel, "", content).replace(f"--- a/{rel}", "--- /dev/null")
                       for rel, content in sorted(files.items()))
        inventory = [{"address": r.address, "service": r.service, "name": r.physical_name,
                      "terraform": f"{r.file}:{r.line}", "name_is_derived": r.interpolated_name}
                     for r in plan.resources]
        derived = [r["address"] for r in inventory if r["name_is_derived"]]
        recommendation = (
            f"Install `moto` (`pip install 'moto[all]'`) and add `{MOCK_DIR}/` to the suite. Tests then exercise the "
            f"real infrastructure shape — {', '.join(plan.services)} — with no AWS account, no credentials and no "
            "cost. Point application code at the mocked clients by constructing boto3 clients inside the function "
            "under test (or by injecting them), never at import time."
            + (f" Terraform computes the names of {', '.join(derived[:5])} from variables, so the mock uses a "
               "deterministic placeholder — override it if your tests assert on the real name." if derived else "")
            + (f" {sum(plan.skipped_types.values())} resource type(s) have no moto equivalent and were skipped: "
               f"{', '.join(sorted(plan.skipped_types))}." if plan.skipped_types else ""))
        result.findings.append(FindingDraft(
            rule_id="coverage:aws-mocks", category="coverage", severity="medium",
            title=f"AWS-dependent code has no mocked fixtures for {len(plan.resources)} Terraform resource(s)",
            description=f"Terraform declares {len(plan.resources)} resource(s) across {len(plan.services)} service(s) "
                        f"({', '.join(plan.services)}) but the test suite has no in-memory AWS. SkyForge generated "
                        f"moto fixtures that mirror those exact resources, so tests never touch a real account.",
            target=plan.resources[0].file, location={"line": plan.resources[0].line},
            evidence={"region": plan.region, "services": plan.services, "resources": inventory,
                      "generated_files": sorted(files), "unsupported_resource_types": plan.skipped_types},
            recommendation=recommendation, confidence="high", data_source="measured",
            fingerprint_key="coverage|aws-mocks",
            proposal=ProposalDraft(
                kind="test_addition", title=f"Add moto-backed AWS fixtures for {len(plan.resources)} resource(s)",
                summary=f"Mocks {', '.join(plan.services)} exactly as Terraform declares them, plus smoke tests that "
                        "fail when Terraform and the fixtures drift apart. Requires moto.",
                diff=diff, files=sorted(files))))
        return plan, files

    # ---------------------------------------------------------------- non-Python languages
    def _polyglot(self, ctx: AgentContext, ws: RepoWorkspace, profile: Any, result: AgentResult) -> list[str]:
        """Inventory and scaffold tests for every non-Python language present. Returns the languages covered."""
        covered: list[str] = []
        limit = int(ctx.options.get("max_scaffolded_languages", 6))
        for language in profile.languages:
            if language in ("python", "terraform", "shell") or len(covered) >= limit:
                continue
            spec = LANGUAGES.get(language)
            if spec is None:
                continue
            ctx.check_cancelled()
            by_file: dict[str, list[Symbol]] = {}
            for path in ws.iter_files(set(spec.exts)):
                rel = ws.rel(path)
                if is_test_path(rel) or rel.startswith(("docs/", "examples/", "vendor/")):
                    continue
                symbols = inventory_symbols(ws, path, language)
                if symbols:
                    by_file[rel] = symbols
                if len(by_file) >= 200:
                    break
            if not by_file:
                continue
            tested = profile.test_files.get(language, 0)
            # Target the files with the most (and most branch-heavy) untested logic first.
            ranked = sorted(by_file.items(), key=lambda kv: -sum(s.complexity for s in kv[1]))
            scaffolds: dict[str, str] = {}
            for rel, symbols in ranked[: int(ctx.options.get("max_generated_tests", 8))]:
                target = test_path_for(rel)
                if not target or ws.exists(target):
                    continue
                content = render_unit_scaffold(language, rel, symbols, source=ws.read_text(rel))
                if content:
                    scaffolds[target] = content
            total_symbols = sum(len(s) for s in by_file.values())
            hotspots = sorted((s for syms in by_file.values() for s in syms), key=lambda s: -s.complexity)[:10]
            proposal = None
            if scaffolds:
                diff = "".join(unified_diff(rel, "", content).replace(f"--- a/{rel}", "--- /dev/null")
                               for rel, content in sorted(scaffolds.items()))
                proposal = ProposalDraft(
                    kind="test_addition",
                    title=f"Add {spec.test_framework} test scaffolds for {len(scaffolds)} {spec.name} file(s)",
                    summary=f"Idiomatic {spec.test_framework} files with one case per edge condition. Every case is "
                            f"skipped/pending, so CI stays green until a developer supplies the expectation. "
                            f"Run with: {spec.runner}",
                    diff=diff, files=sorted(scaffolds))
                for rel, content in scaffolds.items():
                    result.artifacts.append(ArtifactDraft(kind="test_file", name=rel.split("/")[-1], content=content))
            result.findings.append(FindingDraft(
                rule_id=f"coverage:language:{language}", category="coverage",
                severity="high" if not tested and total_symbols >= 20 else ("medium" if not tested else "low"),
                title=(f"{spec.name}: {total_symbols} function(s) across {len(by_file)} file(s) with "
                       f"{'no' if not tested else tested} test file(s)"),
                description=(f"SkyForge inventoried the {spec.name} sources statically (no code executed). "
                             f"Coverage cannot be measured for {spec.name} in the sandbox, so the ranking below uses "
                             "branch count per function."),
                target=ranked[0][0], location={"line": ranked[0][1][0].line},
                evidence={"language": language, "framework": spec.test_framework, "runner": spec.runner,
                          "source_files": len(by_file), "test_files": tested, "functions": total_symbols,
                          "scaffolds": sorted(scaffolds),
                          "start_with": [{"function": s.qualname, "file": s.file, "line": s.line,
                                          "branches": s.complexity} for s in hotspots]},
                recommendation=self._language_advice(spec, hotspots, tested, scaffolds),
                confidence="medium", data_source="estimated", fingerprint_key=f"coverage|lang|{language}",
                proposal=proposal))
            covered.append(language)
            ctx.log(f"{spec.name}: {total_symbols} function(s), {len(scaffolds)} {spec.test_framework} scaffold(s)")
        return covered

    @staticmethod
    def _language_advice(spec: Any, hotspots: list[Symbol], tested: int, scaffolds: dict[str, str]) -> str:
        lines = [f"Add {spec.test_framework} tests for {spec.name} and run them with `{spec.runner}`. "
                 f"Work top-down — this list is ordered by branch count, which is where defects concentrate:"]
        for i, s in enumerate(hotspots[:5], 1):
            args = ", ".join(s.params) or "no arguments"
            lines.append(f"{i}. `{s.qualname}` ({s.file}:{s.line}, ~{s.complexity} branch(es), takes {args}) — "
                         f"cover the happy path, an empty/zero input, a boundary value"
                         + (" and one case per remaining branch." if s.complexity >= 5 else " and one failure case."))
        if scaffolds:
            lines.append(f"SkyForge generated {len(scaffolds)} scaffold file(s) with those cases already named and "
                         f"marked pending — fill in the expectations and remove the skip markers. Assertion style: "
                         f"`{spec.assert_style}`.")
        if not tested:
            lines.append(f"There is no {spec.name} test suite yet: add `{spec.runner}` to CI in the same change so "
                         "coverage cannot regress silently.")
        return "\n".join(lines)

    @staticmethod
    def _roadmap_finding(roadmap: list[dict[str, Any]], baseline: SandboxResult | None,
                         after: SandboxResult | None) -> FindingDraft:
        """A single prioritised 'where to improve coverage next' plan across the whole repository."""
        top = sorted(roadmap, key=lambda r: -r["score"])[:10]
        measured = baseline is not None and baseline.coverage_percent is not None
        current = (after.coverage_percent if after and after.coverage_percent is not None
                   else baseline.coverage_percent if baseline else None)
        total_statements = sum(baseline.statements.values()) if baseline else 0
        planned = sum(r["uncovered_lines"] for r in top)
        lines = ["Improve coverage in this order — modules are ranked by uncovered lines weighted by complexity:"]
        for i, r in enumerate(top, 1):
            where = ", ".join(f"{t['function']} (line {t['line']}, {t['uncovered_lines']} uncovered)"
                              for t in r["start_with"])
            cov_txt = f"at {r['coverage_percent']:.0f}% coverage, " if r["coverage_percent"] is not None else ""
            lines.append(f"{i}. {r['file']} — {cov_txt}{r['uncovered_lines']} uncovered line(s). Start with: {where}.")
        if measured and total_statements:
            lines.append(f"Closing these gaps would move overall coverage from {current:.0f}% to roughly "
                         f"{min(100.0, (current or 0) + 100 * planned / total_statements):.0f}%.")
        else:
            lines.append("Coverage was not measured in a sandbox for this scan, so the ranking is based on static "
                         "analysis (untested public functions weighted by complexity). Enable sandbox execution for "
                         "measured line-level gaps.")
        lines.append("General guidance: test pure functions with boundary inputs first (cheapest coverage), then "
                     "branch-heavy functions one path per test, then wire I/O-dependent code behind fakes so it "
                     "becomes testable.")
        return FindingDraft(
            rule_id="coverage:roadmap", category="coverage", severity="info",
            title=f"Coverage improvement plan: {len(top)} module(s) to target next",
            description=(f"Overall line coverage is {current:.0f}%. " if current is not None else
                         "Overall line coverage was not measured. ")
                        + f"{len(roadmap)} module(s) have uncovered logic; the {len(top)} highest-impact are listed "
                          "with the exact functions and line ranges to test.",
            target="repository", location={},
            evidence={"coverage_percent": current, "measured": measured,
                      "total_uncovered_statements": (sum(baseline.missing_counts.values()) if baseline else None),
                      "modules": top},
            recommendation="\n".join(lines),
            confidence="high" if measured else "medium",
            data_source="measured" if measured else "estimated",
            fingerprint_key="coverage|roadmap")

    @staticmethod
    def _run_draft(r: SandboxResult, label: str, before: float | None) -> TestRunDraft:
        status = r.status if r.status in ("passed", "failed", "error", "not_executed") else "error"
        return TestRunDraft(kind="unit", framework=r.framework, status=status,  # type: ignore[arg-type]
                            total=r.total, passed=r.passed, failed=r.failed, errors=r.errors, skipped=r.skipped,
                            coverage_before=before, coverage_after=r.coverage_percent, duration_s=r.duration_s,
                            details={"label": label, "reason": r.reason, "failures": r.failures[:15],
                                     "coverage_files": dict(list(r.coverage_files.items())[:80])},
                            report_name=_safe_ident(label) + ".log", report_content=r.log_tail or r.reason or label)

    @staticmethod
    def _uncovered(functions: list[FunctionInfo], baseline: SandboxResult) -> set[str]:
        out = set()
        for f in functions:
            missing = set(baseline.missing_lines.get(f.file, []))
            span = set(range(f.line + 1, f.end_line + 1))
            if not baseline.coverage_files or f.file not in baseline.coverage_files or (span and
                                                                                       len(span & missing) / len(span) > 0.5):
                out.add(f"{f.file}:{f.qualname}")
        return out

    def _candidates(self, ctx: AgentContext, functions: list[FunctionInfo], referenced: set[str],
                    uncovered: set[str], exclude: set[str] | None = None) -> list[FunctionInfo]:
        ws: RepoWorkspace = ctx.workspace
        out = []
        globals_cache: dict[str, set[str]] = {}
        for f in functions:
            if exclude and f"{f.file}:{f.qualname}" in exclude:
                continue
            if f.is_method or f.is_async or f.name.startswith("_") or SIDE_EFFECT_NAME.match(f.name):
                continue
            if f.decorators and any(not TRANSPARENT_DECORATOR.match(d) for d in f.decorators):
                continue
            if uncovered and f"{f.file}:{f.qualname}" not in uncovered:
                continue
            if not uncovered and f.name in referenced:
                continue
            source = ws.read_text(f.file)
            src = "\n".join(source.splitlines()[f.line - 1:f.end_line])
            if SIDE_EFFECT_SRC.search(src) or REQUEST_CONTEXT_SRC.search(src):
                continue
            if f.file not in globals_cache:
                globals_cache[f.file] = module_mutable_globals(source)
            if any(re.search(rf"\b{re.escape(g)}\b", src) for g in globals_cache[f.file]):
                continue
            out.append(f)
        out.sort(key=lambda f: -f.complexity)
        return out[: int(ctx.options.get("max_generated_tests", 8)) * 2]

    def _characterize(self, ctx: AgentContext, functions: list[FunctionInfo], referenced: set[str],
                      uncovered: set[str], session: Any,
                      exclude: set[str] | None = None) -> tuple[dict[str, str], dict[str, dict]]:
        cands = [(f, build_cases(f)) for f in self._candidates(ctx, functions, referenced, uncovered, exclude)]
        jobs: list[dict[str, Any]] = [{"id": i, "module": module_name_for(f.file), "function": f.name, "cases": cases}
                for i, (f, cases) in enumerate(cands) if cases]
        if not jobs:
            ctx.log("No deterministic, side-effect-free functions suitable for characterization tests")
            return {}, {}
        session.write_file(".sf_jobs.json", json.dumps(jobs))
        session.write_file(".sf_harness.py", HARNESS)
        code, out = session.python(".sf_harness.py")
        raw = session.read_file(".sf_harness.json")
        if not raw:
            ctx.log(f"Characterization harness produced no output (exit {code})", level="warning")
            return {}, {}
        records = {r["id"]: r for r in json.loads(raw)}
        per_module: dict[str, list[str]] = defaultdict(list)
        imports: dict[str, set[str]] = defaultdict(set)
        counts: dict[str, int] = defaultdict(int)
        limit = int(ctx.options.get("max_generated_tests", 8))
        fn_done = 0
        for job in jobs:
            rec = records.get(job["id"])
            f = cands[job["id"]][0]
            if not rec or rec.get("error"):
                continue
            body: list[str] = []
            route = is_route_handler(f)
            for n, case in enumerate(rec["cases"], 1):
                kind, value, ok, tname = case["first"]
                if not case["stable"] or kind == "timeout" or not ok:
                    continue
                if kind == "raises" and route:
                    # Outside a live request/app context an exception says nothing about the handler's behaviour.
                    continue
                call = f"{f.name}({', '.join(case['args'])})"
                if kind == "value":
                    try:
                        ast.literal_eval(value)
                    except (ValueError, SyntaxError):
                        continue
                    expected = f"pytest.approx({value})" if tname == "float" else value
                    body.append(f"def test_{_safe_ident(f.name)}_case_{n}():\n    assert {call} == {expected}\n")
                else:
                    body.append(f"def test_{_safe_ident(f.name)}_raises_case_{n}():\n"
                                f"    with pytest.raises({value}):\n        {call}\n")
            if not body:
                continue
            mod = module_name_for(f.file)
            rel = generated_test_path(mod)
            per_module[rel] += body
            imports[rel].add(f"from {mod} import {f.name}")
            counts[rel] += len(body)
            per_module[rel + "::module"] = [f.file]
            fn_done += 1
            if fn_done >= limit:
                break
        files: dict[str, str] = {}
        meta: dict[str, dict] = {}
        for rel in [r for r in per_module if not r.endswith("::module")]:
            header = ('"""Characterization tests generated by SkyForge AI (Unit Test & Coverage agent).\n\n'
                      "They pin the current, observed behaviour of deterministic functions so refactors cannot\n"
                      'change it silently. Review each expectation before merging."""\n\nimport pytest\n\n')
            content = header + "\n".join(sorted(imports[rel])) + "\n\n\n" + "\n\n".join(per_module[rel])
            if scan_generated_code(content):
                continue
            files[rel] = content
            meta[rel] = {"module": per_module[rel + "::module"][0], "tests": counts[rel],
                         "strategy": "Characterization (sandbox-observed behaviour)"}
        if files:
            for rel, content in files.items():
                session.write_file(rel, content)
            check = session.pytest(list(files), coverage=False)
            if check.status != "passed":
                failing_files = {fl["test"].split("::")[0].replace(".", "/") for fl in check.failures}
                # Fail closed: when the failures cannot be attributed to specific files (collection errors, nothing
                # collected, a crashed run) every generated file is dropped — a test is only proposed if it passed.
                drop_all = check.status in ("error", "not_executed") or not failing_files
                ctx.log(f"Discarding generated tests that did not pass ({check.status}): "
                        f"{'all' if drop_all else sorted(failing_files)[:5]}", level="warning")
                for rel in list(files):
                    if drop_all or any(rel.replace(".py", "").endswith(ff.split("/")[-1]) for ff in failing_files):
                        files.pop(rel)
                        meta.pop(rel)
                        session.remove_file(rel)
        ctx.log(f"Generated {sum(m['tests'] for m in meta.values())} characterization tests in {len(files)} file(s)")
        return files, meta

    def _llm_tests(self, ctx: AgentContext, ws: RepoWorkspace, functions: list[FunctionInfo], referenced: set[str],
                   uncovered: set[str], session: Any) -> tuple[dict[str, str], dict[str, dict]]:
        llm: LLMService | None = ctx.tool("llm.generate")
        if llm is None or not llm.usable or not ctx.options.get("use_llm", True):
            return {}, {}
        files: dict[str, str] = {}
        meta: dict[str, dict] = {}
        for f in self._candidates(ctx, functions, referenced, uncovered)[: int(ctx.options.get("max_generated_tests", 8))]:
            ctx.check_cancelled()
            src = "\n".join(ws.read_text(f.file).splitlines()[f.line - 1:f.end_line])
            mod = module_name_for(f.file)
            prompt = (f"Write pytest unit tests for the function `{f.name}` from module `{mod}`. "
                      f"Import it with `from {mod} import {f.name}`. Use only pytest and the standard library. "
                      "Assert concrete expected values derived from the code logic; cover edge cases and error "
                      "paths. No network, file system, subprocess or environment access. Output only Python code.\n\n"
                      + wrap_untrusted(src, 4000))
            code = llm.generate(prompt, max_tokens=900)
            if not code:
                continue
            code = re.sub(r"^```(?:python)?\s*|```\s*$", "", code.strip(), flags=re.M)
            try:
                ast.parse(code)
            except SyntaxError:
                continue
            if scan_generated_code(code) or "def test_" not in code:
                continue
            rel = generated_test_path(mod, f.name)
            if session is not None:
                session.write_file(rel, code)
                check = session.pytest([rel], coverage=False)
                if check.status == "failed" and check.passed:
                    # Keep the assertions the model got right; drop only the failing test functions.
                    failing = {fl["test"].split("::")[-1].split("[")[0] for fl in check.failures}
                    pruned = _drop_tests(code, failing)
                    if pruned and "def test_" in pruned:
                        session.write_file(rel, pruned)
                        check = session.pytest([rel], coverage=False)
                        if check.status == "passed":
                            ctx.log(f"LLM test for {f.qualname}: kept {check.passed}, dropped {len(failing)} "
                                    "failing assertion(s)", level="info")
                            code = pruned
                if check.status != "passed":
                    reason = check.failures[0]["message"][:160] if check.failures else (check.reason or check.status)
                    ctx.log(f"LLM test for {f.qualname} failed validation — discarded ({reason})", level="warning")
                    session.remove_file(rel)
                    continue
            files[rel] = code
            meta[rel] = {"module": f.file, "tests": code.count("def test_"),
                         "strategy": f"LLM-drafted ({llm.resolved_model()})", "function": f"{f.file}:{f.qualname}"}
        return files, meta
