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
from typing import Any

from app.adapters.repository.git_repo import RepoWorkspace
from app.adapters.sandbox import DockerSandbox, SandboxResult
from app.adapters.scanners.code_metrics import FunctionInfo, analyse_python_module, is_test_path, module_name_for
from app.adapters.scanners.manifests import unified_diff
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
INT_NAMES = {"n", "num", "count", "i", "j", "k", "x", "y", "size", "limit", "index", "idx", "number", "age", "year",
             "times", "length", "width", "height", "depth", "level", "a", "b"}
STR_NAMES = {"name", "text", "s", "string", "word", "msg", "message", "title", "key", "label", "value", "slug",
             "email", "username", "query", "prefix", "suffix", "sep", "char", "token", "line", "sentence"}
LIST_NAMES = {"items", "values", "lst", "data", "numbers", "nums", "elements", "words", "arr", "array", "seq"}

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


def _safe_ident(s: str) -> str:
    return re.sub(r"[^0-9a-zA-Z_]", "_", s)[:60]


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
    description = "Measures coverage in a sandbox and generates validated unit tests for uncovered logic."
    allowed_tools = frozenset({"repo.read", "static.radon", "sandbox.execute", "llm.generate"})

    def run(self, ctx: AgentContext) -> AgentResult:
        ws: RepoWorkspace = ctx.tool("repo.read")
        result = AgentResult(agent_id="unit_test", tools_used=["ast", "radon"])
        py_files = [p for p in ws.iter_files({".py"}) if not ws.rel(p).startswith(("docs/", "examples/"))]
        sources = [p for p in py_files if not is_test_path(ws.rel(p)) and p.name not in ("setup.py", "conftest.py")
                   and "migrations" not in ws.rel(p)]
        tests = [p for p in py_files if is_test_path(ws.rel(p))]
        js_tests = [p for p in ws.iter_files({".js", ".ts", ".jsx", ".tsx"}) if is_test_path(ws.rel(p))]
        ctx.log(f"Found {len(sources)} Python source files and {len(tests)} Python test files"
                + (f", {len(js_tests)} JS/TS test files" if js_tests else ""))

        if not sources:
            result.notes.append("No Python sources found — coverage measurement is implemented for Python projects; "
                                "JS/TS projects are inventoried only.")
            result.metrics = {"source_files": 0, "test_files": len(tests) + len(js_tests)}
            return result

        modules = [analyse_python_module(ws, p) for p in sources]
        functions = [f for m in modules for f in m.functions]
        test_text = "\n".join(ws.read_text(p) for p in tests)
        referenced = {f.name for f in functions if re.search(rf"\b{re.escape(f.name)}\b", test_text)}
        ctx.progress(0.15, "Source inventory complete")

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
                          "untested_functions": [{"name": f.qualname, "line": f.line, "complexity": f.complexity}
                                                 for f in risky]},
                recommendation="Add focused tests for the highest-complexity untested functions first.",
                confidence="high" if cov is not None else "medium",
                data_source="measured" if cov is not None else "estimated",
                fingerprint_key=f"coverage|{m.file}", proposal=proposal))
            produced += 1
            if produced >= 40:
                break

        for rel, content in generated.items():
            result.artifacts.append(ArtifactDraft(kind="test_file", name=_safe_ident(rel.replace("/", "_"))[:150]
                                                  + ".py", content=content, media_type="text/x-python"))
        total_fns = len(functions)
        result.metrics = {
            "source_files": len(sources), "test_files": len(tests), "functions": total_fns,
            "functions_referenced_by_tests": len(referenced),
            "coverage_before": baseline.coverage_percent if baseline else None,
            "coverage_after": after.coverage_percent if after else None,
            "tests_generated": sum(m["tests"] for m in gen_meta.values()),
            "sandbox_executed": execute,
        }
        ctx.progress(1.0, "Unit test analysis complete")
        return result

    @staticmethod
    def _run_draft(r: SandboxResult, label: str, before: float | None) -> TestRunDraft:
        status = r.status if r.status in ("passed", "failed", "error", "not_executed") else "error"
        return TestRunDraft(kind="unit", framework="pytest", status=status,  # type: ignore[arg-type]
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
        for f in functions:
            if exclude and f"{f.file}:{f.qualname}" in exclude:
                continue
            if f.is_method or f.is_async or f.name.startswith("_") or SIDE_EFFECT_NAME.match(f.name):
                continue
            if f.decorators and any(not d.startswith(("staticmethod", "functools.lru_cache", "lru_cache", "cache"))
                                    for d in f.decorators):
                continue
            if uncovered and f"{f.file}:{f.qualname}" not in uncovered:
                continue
            if not uncovered and f.name in referenced:
                continue
            src = "\n".join(ws.read_text(f.file).splitlines()[f.line - 1:f.end_line])
            if SIDE_EFFECT_SRC.search(src):
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
            for n, case in enumerate(rec["cases"], 1):
                kind, value, ok, tname = case["first"]
                if not case["stable"] or kind == "timeout" or not ok:
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
            rel = f"tests/skyforge_generated/test_{_safe_ident(mod)}.py"
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
            check = session.pytest(list(files), coverage=False)
            if check.status != "passed":
                failing_files = {fl["test"].split("::")[0].replace(".", "/") for fl in check.failures}
                ctx.log(f"Discarding generated tests that did not pass: {sorted(failing_files)[:5]}", level="warning")
                for rel in list(files):
                    if any(rel.replace(".py", "").endswith(ff.split("/")[-1]) for ff in failing_files) or \
                            check.status == "error":
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
            rel = f"tests/skyforge_generated/test_{_safe_ident(mod)}_{_safe_ident(f.name)}.py"
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
