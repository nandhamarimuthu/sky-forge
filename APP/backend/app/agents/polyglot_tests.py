"""Unit testing for JavaScript/TypeScript (node:test) and Go (go test).

Same contract as the Python path: measure the existing suite in the sandbox, draft tests for untested
side-effect-free functions with the local LLM, execute them (network disabled), keep only passing tests and
re-measure. Node's built-in runner works for CommonJS, ESM and (with type stripping) TypeScript without adding
dependencies to the project.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.repository.git_repo import RepoWorkspace
from app.adapters.sandbox import DockerSandbox, SandboxResult, ToolchainSession
from app.adapters.scanners.code_metrics import PolyFunction, analyse_polyglot, is_test_path
from app.adapters.scanners.manifests import unified_diff
from app.agents.base import AgentContext
from app.agents.security_guardrails import scan_generated_code
from app.schemas.agents import ArtifactDraft, FindingDraft, ProposalDraft, TestRunDraft
from app.services.llm import LLMService, wrap_untrusted

NODE_IMAGE = "node:22-slim"
GO_IMAGE = "golang:1.22-alpine"
GO_ENV = {"GOFLAGS": "-mod=mod", "GOCACHE": "/work/.sf_go/cache", "GOPATH": "/work/.sf_go/path",
          "GOTOOLCHAIN": "local", "CGO_ENABLED": "0"}
JS_EXTS = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
SIDE_EFFECT_JS = re.compile(r"\b(fetch\(|axios|require\(['\"](fs|child_process|http|https|net|dgram)['\"]|"
                            r"process\.(env|exit)|Date\.now|new Date\(\s*\)|Math\.random|document\.|window\.|"
                            r"localStorage|setTimeout|setInterval|console\.|\.listen\(|await )")
SIDE_EFFECT_GO = re.compile(r"\b(os\.|http\.|net\.|exec\.|time\.Now|rand\.|sql\.|ioutil\.|bufio\.|fmt\.Print|"
                            r"log\.|go func|<-|chan )")
NPM_DEFAULT_TEST = "no test specified"


@dataclass
class PolyOutcome:
    findings: list[FindingDraft] = field(default_factory=list)
    test_runs: list[TestRunDraft] = field(default_factory=list)
    artifacts: list[ArtifactDraft] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    tools: set[str] = field(default_factory=set)


def _safe(s: str) -> str:
    return re.sub(r"[^0-9a-zA-Z_]", "_", s)[:60]


def _block_end(code: str, open_idx: int, opener: str, closer: str) -> int:
    """Index just past the bracket matching code[open_idx], skipping string/char literals and comments."""
    depth, i, quote = 0, open_idx, ""
    while i < len(code):
        ch = code[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "'\"`":
            quote = ch
        elif code.startswith("//", i):
            nl = code.find("\n", i)
            i = len(code) if nl < 0 else nl
            continue
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def drop_js_tests(code: str, names: set[str]) -> str | None:
    out = code
    for name in names:
        m = re.search(r"(?m)^[ \t]*(?:test|it)\(\s*(['\"`])" + re.escape(name) + r"\1", out)
        if not m:
            return None
        end = _block_end(out, out.index("(", m.start()), "(", ")")
        if end < 0:
            return None
        if out[end:end + 1] == ";":
            end += 1
        out = out[:m.start()] + out[end:]
    return out


def drop_go_tests(code: str, names: set[str]) -> str | None:
    out = code
    for name in names:
        m = re.search(r"(?m)^func " + re.escape(name) + r"\(t \*testing\.T\)\s*\{", out)
        if not m:
            return None
        end = _block_end(out, m.end() - 1, "{", "}")
        if end < 0:
            return None
        out = out[:m.start()] + out[end:]
    return out


def _strip_fences(code: str) -> str:
    return re.sub(r"^```[a-zA-Z]*\s*|```\s*$", "", code.strip(), flags=re.M).strip() + "\n"


# ---------------------------------------------------------------------- JavaScript / TypeScript
def _js_exports(text: str) -> set[str]:
    names = set(re.findall(r"(?m)^export\s+(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)", text))
    names |= set(re.findall(r"(?m)^export\s+const\s+([A-Za-z_$][\w$]*)\s*=", text))
    names |= set(re.findall(r"(?m)^(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=", text))
    for body in re.findall(r"module\.exports\s*=\s*\{([^}]*)\}", text):
        names |= {p.split(":")[0].strip() for p in body.split(",") if re.match(r"^\s*[A-Za-z_$][\w$]*", p)}
    for body in re.findall(r"(?m)^export\s*\{([^}]*)\}", text):
        names |= {n.split(" as ")[-1].strip() for n in body.split(",") if n.strip()}
    return {n for n in names if n}


def _js_kind(ws: RepoWorkspace, rel: str, text: str) -> str:
    ext = Path(rel).suffix
    if ext in (".ts", ".mts", ".cts"):
        return "ts"
    if ext == ".mjs":
        return "esm"
    if ext == ".cjs":
        return "cjs"
    pkg = ws.root / "package.json"
    try:
        if pkg.is_file() and json.loads(pkg.read_text()).get("type") == "module":
            return "esm"
    except (json.JSONDecodeError, OSError):
        pass
    return "esm" if re.search(r"(?m)^export\s", text) else "cjs"


def _tap(out: str) -> tuple[int, int, set[str], float | None]:
    passed = int(m.group(1)) if (m := re.search(r"(?m)^# pass (\d+)", out)) else 0
    failed = int(m.group(1)) if (m := re.search(r"(?m)^# fail (\d+)", out)) else 0
    failing = {m.group(1).strip() for m in re.finditer(r"(?m)^\s*not ok \d+ - (.+?)\s*$", out)}
    cov = float(m.group(1)) if (m := re.search(r"(?m)^#\s*all files\s*\|\s*([\d.]+)", out)) else None
    return passed, failed, failing, cov


def _node_cmd(files: list[str], coverage: bool = False) -> str:
    cov = "--experimental-test-coverage " if coverage else ""
    return (f"node --experimental-strip-types --no-warnings --test --test-reporter=tap {cov}"
            + " ".join(f"'{f}'" for f in files))


def _js_run(ctx: AgentContext, ws: RepoWorkspace, sandbox: DockerSandbox | None, llm: LLMService | None,
            fns: list[PolyFunction], test_text: str, out: PolyOutcome, limit: int) -> None:
    pkg: dict[str, Any] = {}
    try:
        pkg = json.loads(ws.read_text("package.json")) if (ws.root / "package.json").is_file() else {}
    except json.JSONDecodeError:
        pkg = {}
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
    test_script = (pkg.get("scripts") or {}).get("test", "")
    referenced = {f.name for f in fns if re.search(rf"\b{re.escape(f.name)}\b", test_text)}
    by_file: dict[str, list[PolyFunction]] = defaultdict(list)
    for f in fns:
        by_file[f.file].append(f)
    candidates: list[tuple[PolyFunction, str, str]] = []
    for rel, items in by_file.items():
        text = ws.read_text(rel)
        exported = _js_exports(text)
        lines = text.splitlines()
        for f in items:
            src = "\n".join(lines[f.line - 1:f.end_line])
            if f.name in exported and f.name not in referenced and not SIDE_EFFECT_JS.search(src) \
                    and f.end_line - f.line < 120:
                candidates.append((f, src, _js_kind(ws, rel, text)))
    candidates.sort(key=lambda c: -c[0].complexity)
    out.metrics["js_functions"] = len(fns)
    out.metrics["js_untested_exported"] = len(candidates)

    generated: dict[str, str] = {}
    meta: dict[str, dict[str, Any]] = {}
    baseline_cov: float | None = None
    after_cov: float | None = None
    session: ToolchainSession | None = None
    if sandbox is not None and sandbox.available():
        session = sandbox.toolchain(ws.root, NODE_IMAGE, {"CI": "true", "npm_config_cache": "/tmp/npm"})  # noqa: S108 - tmpfs inside the container
        session.__enter__()
    try:
        if session is not None:
            install = ("npm ci --ignore-scripts --no-audit --no-fund --loglevel=error || "
                       "npm install --ignore-scripts --no-audit --no-fund --loglevel=error") if deps else ""
            ctx.log(f"Installing Node dependencies in the sandbox ({NODE_IMAGE})" if deps else
                    f"Preparing Node sandbox ({NODE_IMAGE})")
            err = session.prepare(install, cache_paths=["node_modules"] if deps else [],
                                  key_files=["package.json", "package-lock.json", "npm-shrinkwrap.json"])
            if err:
                ctx.log(f"Node sandbox unavailable: {err.reason}", level="warning")
                out.test_runs.append(TestRunDraft(kind="unit", framework="node", status="error",
                                                  details={"label": "JS/TS dependency install",
                                                           "reason": err.reason, "log": err.log_tail[-1500:]}))
                session.__exit__(None, None, None)
                session = None
        if session is not None and test_script and NPM_DEFAULT_TEST not in test_script:
            rc, log = session.sh("npm test --silent 2>&1 | tail -c 20000")
            passed, failed, _, _ = _tap(log)
            status = "passed" if rc == 0 else "failed"
            jest = re.search(r"Tests:\s+(?:(\d+) failed, )?(?:\d+ skipped, )?(\d+) passed, (\d+) total", log)
            total = int(jest.group(3)) if jest else passed + failed
            ok = int(jest.group(2)) if jest else passed
            ctx.log(f"Existing JS/TS suite (`npm test`): {status}" + (f", {ok}/{total} passed" if total else ""))
            out.test_runs.append(TestRunDraft(kind="unit", framework="npm test", status=status,  # type: ignore[arg-type]
                                              total=total, passed=ok, failed=max(0, total - ok),
                                              details={"label": "Baseline (existing JS/TS tests)"},
                                              report_name="npm_test.log", report_content=log[-20000:]))
            out.tools.add("npm test")
            if rc != 0:
                out.findings.append(FindingDraft(
                    rule_id="tests:failing-suite", category="coverage", severity="high",
                    title="Existing JavaScript/TypeScript test suite fails", target="package.json",
                    description="`npm test` exited non-zero inside the sandbox (network disabled).",
                    evidence={"log_tail": log[-1500:]}, recommendation="Fix the failing tests before adding new ones.",
                    confidence="high", data_source="measured", fingerprint_key="tests|js|failing"))

        usable_llm = llm is not None and llm.usable and ctx.options.get("use_llm", True)
        picks = candidates[:limit] if usable_llm and ctx.options.get("generate_tests", True) else []

        def draft(c: tuple[PolyFunction, str, str]) -> str | None:
            f, src, kind = c
            depth = "../" * 2
            target = f"{depth}{f.file}"
            imp = (f"const {{ {f.name} }} = require('{target}');" if kind == "cjs"
                   else f"import {{ {f.name} }} from '{target}';")
            prompt = (f"Write unit tests for the {'TypeScript' if kind == 'ts' else 'JavaScript'} function "
                      f"`{f.name}` using ONLY Node's built-in test runner.\nStart with exactly these lines:\n"
                      + ("const test = require('node:test');\nconst assert = require('node:assert/strict');\n"
                         if kind == "cjs" else
                         "import test from 'node:test';\nimport assert from 'node:assert/strict';\n")
                      + imp + "\nRules:\n- One `test('<function> <scenario>', () => { ... })` per scenario.\n"
                      "- Trace the code by hand and assert exact values the CURRENT code returns (assert.equal / "
                      "assert.deepEqual / assert.throws).\n- Cover typical input, boundaries (0, empty, null/undefined "
                      "where accepted) and every branch.\n- No other imports, no network, timers, randomness or "
                      "filesystem. Output only code.\n\n" + wrap_untrusted(src, 4000))
            assert llm is not None
            return llm.generate(prompt, max_tokens=1100)

        if picks:
            ctx.log(f"Drafting JS/TS tests for {len(picks)} untested exported function(s) with "
                    f"{llm.resolved_model() if llm else 'LLM'}")
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="llm-js") as pool:
                drafts = list(pool.map(draft, picks))
            for (f, _src, kind), code in zip(picks, drafts, strict=True):
                ctx.check_cancelled()
                if not code:
                    continue
                code = _strip_fences(code)
                if "node:test" not in code or scan_generated_code(code):
                    continue
                ext = ".cjs" if kind == "cjs" else ".mjs"
                rel = f"tests/skyforge_generated/{_safe(Path(f.file).stem)}_{_safe(f.name)}.test{ext}"
                if session is not None:
                    session.write_file(rel, code)
                    _c, log = session.sh(_node_cmd([rel]), timeout=120)
                    passed, failed, failing, _ = _tap(log)
                    if failed and passed and failing:
                        pruned = drop_js_tests(code, failing)
                        if pruned and re.search(r"(?m)^\s*(test|it)\(", pruned):
                            session.write_file(rel, pruned)
                            _c, log = session.sh(_node_cmd([rel]), timeout=120)
                            passed, failed, failing, _ = _tap(log)
                            if not failed and passed:
                                code = pruned
                                ctx.log(f"JS test for {f.name}: kept {passed}, dropped failing assertion(s)")
                    if failed or not passed:
                        reason = next((ln.strip() for ln in log.splitlines() if "Error" in ln), "no passing tests")
                        ctx.log(f"JS test for {f.name} failed validation — discarded ({reason[:140]})",
                                level="warning")
                        session.remove_file(rel)
                        continue
                generated[rel] = code
                meta[rel] = {"module": f.file, "tests": len(re.findall(r"(?m)^\s*(?:test|it)\(", code)),
                             "function": f.name}
        if session is not None:
            js_sources = sorted({c[0].file for c in candidates} | {f.file for f in fns})[:200]
            if generated:
                _c, log = session.sh(_node_cmd(sorted(generated), coverage=True), timeout=300)
                passed, failed, _, after_cov = _tap(log)
                ctx.log(f"Generated JS/TS tests: {passed} passed, {failed} failed"
                        + (f"; coverage of loaded files {after_cov}%" if after_cov is not None else ""))
                out.test_runs.append(TestRunDraft(kind="unit", framework="node:test",
                                                  status="passed" if not failed else "failed",
                                                  total=passed + failed, passed=passed, failed=failed,
                                                  coverage_before=baseline_cov, coverage_after=after_cov,
                                                  details={"label": "SkyForge-generated JS/TS tests",
                                                           "sources": js_sources[:20]},
                                                  report_name="node_test.tap", report_content=log[-20000:]))
            out.tools.add("node:test")
    finally:
        if session is not None:
            session.__exit__(None, None, None)
    _emit_findings(out, "JavaScript/TypeScript", candidates, generated, meta, executed=session is not None,
                   strategy=f"LLM-drafted node:test ({llm.resolved_model() if llm else 'LLM'})")


# ---------------------------------------------------------------------- Go
def _go_json(out: str) -> tuple[int, int, set[str]]:
    passed = failed = 0
    failing: set[str] = set()
    for line in out.splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(ev, dict) or not ev.get("Test") or "/" in ev["Test"]:
            continue
        if ev.get("Action") == "pass":
            passed += 1
        elif ev.get("Action") == "fail":
            failed += 1
            failing.add(ev["Test"])
    return passed, failed, failing


def _go_cov(text: str | None) -> float | None:
    m = re.search(r"total:\s+\(statements\)\s+([\d.]+)%", text or "")
    return float(m.group(1)) if m else None


def _go_run(ctx: AgentContext, ws: RepoWorkspace, sandbox: DockerSandbox | None, llm: LLMService | None,
            fns: list[PolyFunction], test_text: str, out: PolyOutcome, limit: int) -> None:
    referenced = {f.name for f in fns if re.search(rf"\b{re.escape(f.name)}\b", test_text)}
    candidates: list[tuple[PolyFunction, str, str]] = []
    pkg_of: dict[str, str] = {}
    for f in fns:
        if f.file not in pkg_of:
            m = re.search(r"(?m)^package\s+(\w+)", ws.read_text(f.file))
            pkg_of[f.file] = m.group(1) if m else ""
        lines = ws.read_text(f.file).splitlines()
        header = lines[f.line - 1] if f.line <= len(lines) else ""
        src = "\n".join(lines[f.line - 1:f.end_line])
        if (pkg_of[f.file] and pkg_of[f.file] != "main" and re.match(r"^func [A-Za-z_]\w*\(", header)
                and f.name not in ("init", "main") and f.name not in referenced and not SIDE_EFFECT_GO.search(src)
                and f.end_line - f.line < 120):
            candidates.append((f, src, pkg_of[f.file]))
    candidates.sort(key=lambda c: -c[0].complexity)
    out.metrics["go_functions"] = len(fns)
    out.metrics["go_untested"] = len(candidates)
    generated: dict[str, str] = {}
    meta: dict[str, dict[str, Any]] = {}
    session: ToolchainSession | None = None
    if sandbox is not None and sandbox.available():
        session = sandbox.toolchain(ws.root, GO_IMAGE, GO_ENV)
        session.__enter__()
    run_all = ("go test ./... -count=1 -json -coverprofile=/work/.sf_cover.out > /work/.sf_gotest.json 2>&1; "
               "rc=$?; go tool cover -func=/work/.sf_cover.out > /work/.sf_cover.txt 2>/dev/null; exit $rc")
    try:
        if session is not None:
            ctx.log(f"Downloading Go modules in the sandbox ({GO_IMAGE})")
            err = session.prepare("go mod download 2>&1 | tail -20", cache_paths=[".sf_go"],
                                  key_files=["go.mod", "go.sum"])
            if err:
                ctx.log(f"Go sandbox unavailable: {err.reason}", level="warning")
                session.__exit__(None, None, None)
                session = None
        before: float | None = None
        if session is not None:
            rc, _log = session.sh(run_all)
            raw = session.read_file(".sf_gotest.json") or ""
            passed, failed, _ = _go_json(raw)
            before = _go_cov(session.read_file(".sf_cover.txt"))
            ctx.log(f"Existing Go tests: {passed} passed, {failed} failed, coverage {before}%")
            out.test_runs.append(TestRunDraft(kind="unit", framework="go test",
                                              status="passed" if rc == 0 else ("failed" if passed + failed else "error"),
                                              total=passed + failed, passed=passed, failed=failed,
                                              coverage_after=before, details={"label": "Baseline (existing Go tests)"},
                                              report_name="go_test.json", report_content=raw[-20000:]))
            out.metrics["go_coverage_before"] = before
            out.tools.add("go test")

        usable_llm = llm is not None and llm.usable and ctx.options.get("use_llm", True)
        picks = candidates[:limit] if usable_llm and ctx.options.get("generate_tests", True) else []

        def draft(c: tuple[PolyFunction, str, str]) -> str | None:
            f, src, pkg = c
            prompt = (f"Write Go unit tests for the function `{f.name}` in package `{pkg}`.\nRules:\n"
                      f"- File starts with `package {pkg}` and imports only \"testing\" (plus \"reflect\" or "
                      "\"strings\" only if actually used).\n"
                      f"- Every test function name starts with `TestSkyforge{f.name}` and has signature "
                      "(t *testing.T).\n- Use table-driven tests with t.Run; trace the code by hand and assert the "
                      "exact values the CURRENT code returns; cover boundaries and every branch.\n"
                      "- No network, filesystem, time or randomness. Output only Go code.\n\n"
                      + wrap_untrusted(src, 4000))
            assert llm is not None
            return llm.generate(prompt, max_tokens=1100)

        if picks:
            ctx.log(f"Drafting Go tests for {len(picks)} untested function(s)")
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="llm-go") as pool:
                drafts = list(pool.map(draft, picks))
            for (f, _src, pkg), code in zip(picks, drafts, strict=True):
                ctx.check_cancelled()
                if not code:
                    continue
                code = _strip_fences(code)
                if not code.startswith(f"package {pkg}") or scan_generated_code(code):
                    continue
                rel = str(Path(f.file).with_name(f"{Path(f.file).stem}_{_safe(f.name).lower()}_skyforge_test.go"))
                pkg_dir = "./" + (str(Path(f.file).parent) if str(Path(f.file).parent) != "." else "")
                if session is not None:
                    session.write_file(rel, code)
                    run_one = f"go test {pkg_dir} -run '^TestSkyforge{f.name}' -count=1 -json 2>&1"
                    _c, log = session.sh(run_one, timeout=300)
                    passed, failed, failing = _go_json(log)
                    if failed and passed:
                        pruned = drop_go_tests(code, {t for t in failing if t.startswith("TestSkyforge")})
                        if pruned and "func TestSkyforge" in pruned:
                            session.write_file(rel, pruned)
                            _c, log = session.sh(run_one, timeout=300)
                            passed, failed, failing = _go_json(log)
                            if not failed and passed:
                                code = pruned
                                ctx.log(f"Go test for {f.name}: kept {passed}, dropped failing test(s)")
                    if failed or not passed:
                        reason = next((ln for ln in log.splitlines() if "Output" in ln and ("error" in ln.lower()
                                                                                           or "FAIL" in ln)), "")
                        ctx.log(f"Go test for {f.name} failed validation — discarded {reason[:140]}",
                                level="warning")
                        session.remove_file(rel)
                        continue
                generated[rel] = code
                meta[rel] = {"module": f.file, "tests": code.count("func TestSkyforge"), "function": f.name}
        if session is not None and generated:
            rc, _log = session.sh(run_all)
            raw = session.read_file(".sf_gotest.json") or ""
            passed, failed, _ = _go_json(raw)
            after = _go_cov(session.read_file(".sf_cover.txt"))
            ctx.log(f"Go suite with generated tests: {passed} passed, {failed} failed, coverage {after}%")
            out.test_runs.append(TestRunDraft(kind="unit", framework="go test",
                                              status="passed" if rc == 0 else "failed", total=passed + failed,
                                              passed=passed, failed=failed, coverage_before=before,
                                              coverage_after=after,
                                              details={"label": "With SkyForge-generated Go tests"},
                                              report_name="go_test_after.json", report_content=raw[-20000:]))
            out.metrics["go_coverage_after"] = after
    finally:
        if session is not None:
            session.__exit__(None, None, None)
    _emit_findings(out, "Go", candidates, generated, meta, executed=session is not None,
                   strategy=f"LLM-drafted go test ({llm.resolved_model() if llm else 'LLM'})")


# ---------------------------------------------------------------------- shared
def _emit_findings(out: PolyOutcome, language: str, candidates: list[tuple[PolyFunction, str, str]],
                   generated: dict[str, str], meta: dict[str, dict[str, Any]], executed: bool, strategy: str) -> None:
    by_module: dict[str, list[PolyFunction]] = defaultdict(list)
    for f, _src, _k in candidates:
        by_module[f.file].append(f)
    for module, items in sorted(by_module.items(), key=lambda kv: -max(f.complexity for f in kv[1]))[:30]:
        gen = {rel: c for rel, c in generated.items() if meta[rel]["module"] == module}
        proposal = None
        if gen:
            diff = "".join(unified_diff(rel, "", c).replace(f"--- a/{rel}", "--- /dev/null") for rel, c in gen.items())
            n = sum(meta[r]["tests"] for r in gen)
            proposal = ProposalDraft(kind="test_addition", title=f"Add {n} generated {language} test(s) for {module}",
                                     summary=f"{strategy}. " + ("Executed in the sandbox: all proposed tests pass."
                                                                if executed else "Not executed — review carefully."),
                                     diff=diff, files=list(gen))
        risky = sorted(items, key=lambda f: -f.complexity)[:8]
        out.findings.append(FindingDraft(
            rule_id="coverage:module", category="coverage",
            severity="medium" if any(f.complexity >= 10 for f in risky) else "low",
            title=f"{module}: {len(items)} {language} function(s) without tests",
            description="Untested logic: " + ", ".join(f"{f.name} (CC {f.complexity})" for f in risky),
            target=module, location={"line": risky[0].line},
            evidence={"language": language, "measured": False,
                      "untested_functions": [{"name": f.name, "line": f.line, "complexity": f.complexity}
                                             for f in risky]},
            recommendation="Add focused unit tests for the highest-complexity functions first.",
            confidence="medium", data_source="estimated", fingerprint_key=f"coverage|{module}", proposal=proposal))
    for rel, content in generated.items():
        out.artifacts.append(ArtifactDraft(kind="test_file", name=_safe(rel.replace("/", "_"))[:150] + Path(rel).suffix,
                                           content=content, media_type="text/plain"))


def run_polyglot_unit_tests(ctx: AgentContext, ws: RepoWorkspace, sandbox: DockerSandbox | None,
                            llm: LLMService | None, limit: int) -> PolyOutcome:
    out = PolyOutcome()
    fns, _sloc = analyse_polyglot(ws)
    js = [f for f in fns if f.file.endswith(JS_EXTS) and not f.name.startswith("(")]
    go = [f for f in fns if f.file.endswith(".go")]
    tests = [p for p in ws.iter_files(set(JS_EXTS) | {".go"}) if is_test_path(ws.rel(p))]
    test_text = "\n".join(ws.read_text(p) for p in tests[:400])
    out.metrics["test_files_other"] = len(tests)
    if js:
        _js_run(ctx, ws, sandbox, llm, js, test_text, out, limit)
    if go and (ws.root / "go.mod").is_file():
        _go_run(ctx, ws, sandbox, llm, go, test_text, out, limit)
    others = sorted({f.language for f in fns} - {"js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "go"})
    if others:
        out.metrics["languages_inventoried_only"] = others
    return out


__all__ = ["PolyOutcome", "SandboxResult", "drop_go_tests", "drop_js_tests", "run_polyglot_unit_tests"]
