"""Agent 5 — Code Health Agent.

Uses Ruff (lint), Radon (cyclomatic complexity, maintainability index), a duplication detector and git churn to
find hotspots, and proposes Ruff safe fixes and narrowly audited JavaScript refactors as reviewable diffs.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import cast

from app.adapters.repository.git_repo import RepositoryError, RepoWorkspace, run_git
from app.adapters.scanners.code_metrics import (
    CODE_EXTS,
    JS_EXTS,
    RUFF_SAFE_FIX_RULES,
    analyse_python_module,
    find_dead_js_imports,
    find_duplicates,
    is_test_path,
    ruff_fix_diff,
    run_ruff,
)
from app.adapters.scanners.js_refactor import aggregation_refactor, fix_unused_requires
from app.adapters.scanners.manifests import unified_diff
from app.agents.base import AgentContext, BaseAgent
from app.schemas.agents import AgentResult, FindingDraft, ProposalDraft

SAFE_PREFIXES = tuple(r for r in RUFF_SAFE_FIX_RULES.split(","))


def churn(ws: RepoWorkspace, limit: int = 50) -> Counter[str]:
    try:
        out = run_git(["log", f"-n{limit}", "--name-only", "--pretty=format:"], cwd=ws.root, timeout=30)
    except RepositoryError:
        return Counter()
    return Counter(line.strip() for line in out.splitlines() if line.strip())


class CodeHealthAgent(BaseAgent):
    id = "code_health"
    name = "Code Health"
    code = "Code Health"
    description = ("Measures complexity, duplication, lint and maintainability, then proposes safe refactors "
                   "for the riskiest files.")
    allowed_tools = frozenset({"repo.read", "static.ruff", "static.radon"})

    def run(self, ctx: AgentContext) -> AgentResult:
        ws: RepoWorkspace = ctx.tool("repo.read")
        ctx.tool("static.radon")
        result = AgentResult(agent_id="code_health", tools_used=["radon", "ruff", "duplication-detector", "git-churn"])
        py = [p for p in ws.iter_files({".py"}) if not is_test_path(ws.rel(p))]
        modules = [analyse_python_module(ws, p) for p in py]
        ctx.progress(0.3, f"Analysed {len(modules)} Python modules")
        ctx.check_cancelled()

        lint = run_ruff(ws.root) if ctx.has_tool("static.ruff") and py else []
        ctx.tool("static.ruff")
        lint = [v for v in lint if not str(v.get("code", "")).startswith("S")]  # security rules belong to Security Guardrails
        ctx.progress(0.5, f"Ruff reported {len(lint)} findings")
        dups = find_duplicates(ws)
        ctx.progress(0.7, f"{len(dups)} duplicated blocks")
        hot = churn(ws)

        functions = [f for m in modules for f in m.functions]
        for f in sorted(functions, key=lambda f: -f.complexity):
            if f.complexity < 15:
                break
            length = f.end_line - f.line + 1
            result.findings.append(FindingDraft(
                rule_id="health:complexity", category="code_health",
                severity="high" if f.complexity >= 30 else "medium",
                title=f"{f.qualname} has cyclomatic complexity {f.complexity}",
                description=f"{length} lines in {f.file}. High complexity correlates with defects and makes testing "
                            "hard.", target=f.file, location={"line": f.line, "end_line": f.end_line},
                evidence={"complexity": f.complexity, "lines": length, "churn": hot.get(f.file, 0)},
                recommendation="Extract cohesive branches into helper functions or use a dispatch table; add tests "
                               "before refactoring.", confidence="high", fingerprint_key=f"cc|{f.file}|{f.qualname}"))
        for f in functions:
            length = f.end_line - f.line + 1
            if length > 100 and f.complexity < 15:
                result.findings.append(FindingDraft(
                    rule_id="health:long-function", category="code_health", severity="low",
                    title=f"{f.qualname} is {length} lines long", target=f.file, location={"line": f.line},
                    evidence={"lines": length, "complexity": f.complexity},
                    recommendation="Split into smaller functions with single responsibilities.", confidence="high",
                    fingerprint_key=f"len|{f.file}|{f.qualname}"))
        for m in modules:
            if m.parse_error:
                result.findings.append(FindingDraft(
                    rule_id="health:syntax-error", category="code_health", severity="high",
                    title=f"{m.file} does not parse", description=m.parse_error, target=m.file,
                    recommendation="Fix the syntax error; the module cannot be imported.", confidence="high",
                    fingerprint_key=f"syntax|{m.file}"))
            elif m.maintainability is not None and m.maintainability < 20 and m.sloc > 40:
                result.findings.append(FindingDraft(
                    rule_id="health:maintainability", category="code_health",
                    severity="medium" if m.maintainability < 10 else "low",
                    title=f"{m.file} has low maintainability index ({m.maintainability})", target=m.file,
                    evidence={"maintainability_index": m.maintainability, "sloc": m.sloc,
                              "functions": len(m.functions)},
                    recommendation="Reduce module size and complexity; split responsibilities.", confidence="high",
                    fingerprint_key=f"mi|{m.file}"))
        for d in dups[:25]:
            files = ", ".join(f"{f}:{ln}" for f, ln in d.occurrences[:4])
            result.findings.append(FindingDraft(
                rule_id="health:duplication", category="code_health", severity="low",
                title=f"Duplicated block ({d.lines}+ lines) in {len(d.occurrences)} places",
                description=files, target=d.occurrences[0][0], location={"line": d.occurrences[0][1]},
                evidence={"occurrences": [{"file": f, "line": ln} for f, ln in d.occurrences]},
                recommendation="Extract the shared logic into a single function/module.", confidence="medium",
                fingerprint_key=f"dup|{d.hash}"))

        by_file: dict[str, list[dict]] = defaultdict(list)
        for v in lint:
            rel = ws.rel(ws.root / v["filename"]) if v.get("filename", "").startswith("/") else v.get("filename", "")
            by_file[rel].append(v)

        def safe_fixable(violations: list[dict]) -> int:
            return sum(1 for v in violations
                       if str(v.get("code", "")).startswith(SAFE_PREFIXES) and v.get("fix"))

        fixable_files = sorted(f for f, vs in by_file.items() if safe_fixable(vs))
        proposed_per_file: set[str] = set()
        for rel, vs in sorted(by_file.items(), key=lambda kv: -len(kv[1]))[:30]:
            if len(vs) < 5:
                continue
            ctx.check_cancelled()
            codes = Counter(v["code"] for v in vs)
            # Each lint hotspot carries its own patch, so it can be approved, verified and turned into a PR on its own.
            proposal = None
            n_fixable = safe_fixable(vs)
            if n_fixable:
                diff = ruff_fix_diff(ws.root, [rel])
                if diff.strip():
                    proposal = ProposalDraft(
                        kind="refactor", title=f"Apply {n_fixable} Ruff safe fix(es) to {rel}",
                        summary=f"Expected lint count in this file: {len(vs)} → {len(vs) - n_fixable}. Only fixes "
                                "Ruff marks as safe (unused imports, outdated syntax, redundant constructs) — no "
                                "behaviour change.", diff=diff, files=[rel])
                    proposed_per_file.add(rel)
            result.findings.append(FindingDraft(
                rule_id="health:lint", category="code_health", severity="low",
                title=f"{len(vs)} lint issues in {rel}", description=", ".join(f"{c}×{n}" for c, n in codes.most_common(8)),
                target=rel, location={"line": vs[0].get("location", {}).get("row", 1)},
                evidence={"by_rule": dict(codes.most_common(20)), "safe_fixable": n_fixable,
                          "samples": [{"code": v["code"], "message": v["message"],
                                       "line": v.get("location", {}).get("row")} for v in vs[:10]]},
                recommendation="Apply the proposed patch, then fix the remaining rules by frequency; enable Ruff in "
                               "CI." if proposal else "Fix the most frequent rules first; enable Ruff in CI.",
                confidence="high", fingerprint_key=f"lint|{rel}", proposal=proposal))

        # Everything left over (small files, or beyond the per-file cap) is batched into one patch so no safe fix is
        # stranded. Files that already have their own proposal are excluded to keep patches non-overlapping.
        remaining = [f for f in fixable_files if f not in proposed_per_file]
        if remaining:
            ctx.check_cancelled()
            subset = remaining[:15]
            diff = ruff_fix_diff(ws.root, subset)
            fixable_count = sum(safe_fixable(by_file[f]) for f in subset)
            if diff.strip():
                result.findings.append(FindingDraft(
                    rule_id="health:autofix", category="code_health", severity="low",
                    title=f"{fixable_count} behaviour-preserving lint fixes available in {len(subset)} file(s)",
                    description="Unused imports, outdated syntax and redundant constructs that Ruff can fix safely.",
                    target=subset[0], evidence={"files": subset, "fixable": fixable_count,
                                                "lint_before": len(lint), "lint_after_expected": len(lint) - fixable_count},
                    recommendation="Apply the proposed refactor patch.", confidence="high",
                    fingerprint_key="autofix|ruff-safe",
                    proposal=ProposalDraft(kind="refactor", title=f"Apply Ruff safe fixes to {len(subset)} file(s)",
                                           summary=f"Expected lint count: {len(lint)} → {len(lint) - fixable_count}. "
                                                   "Only fixes Ruff marks as safe (no behaviour change).",
                                           diff=diff, files=subset)))


        # Closed aggregation clones can be consolidated without inventing fixes for
        # arbitrary duplication. Only existing files and inert CommonJS utilities qualify.
        js_sources = {ws.rel(p): ws.read_text(p) for p in ws.iter_files(JS_EXTS, max_bytes=300_000)
                      if not is_test_path(ws.rel(p))}
        aggregation = aggregation_refactor(js_sources)
        if aggregation:
            diff = "".join(unified_diff(rel, js_sources[rel], after)
                           for rel, after in sorted(aggregation.changes.items()))
            result.findings.append(FindingDraft(
                rule_id="health:duplicate-aggregation", category="code_health", severity="low",
                title=f"Share identical aggregation logic across {len(aggregation.occurrences)} modules",
                target=aggregation.occurrences[0][0], location={"line": aggregation.occurrences[0][1]},
                description="Identical record counting, amount rounding and status aggregation in named service functions.",
                evidence={"occurrences": [{"file": f, "line": line} for f, line in aggregation.occurrences],
                          "helper_file": aggregation.helper_file, "detector": "audited-closed-body-token-match"},
                recommendation="Review the shared helper and run the repository tests in the sandbox before merging.",
                confidence="high", fingerprint_key=f"dup-aggregation|{aggregation.helper_file}",
                proposal=ProposalDraft(
                    kind="refactor", title="Extract duplicated record aggregation into a shared utility",
                    summary="Preserves named wrappers, signatures, coercion, rounding and fresh per-call objects. "
                            "Moves the exact closed aggregation body into an existing initialization-free CommonJS "
                            "utility; wrappers load it lazily. No scanned repository code was executed.",
                    diff=diff, files=sorted(aggregation.changes))))

        js_dead = 0
        for path in ws.iter_files(JS_EXTS, max_bytes=300_000):
            rel = ws.rel(path)
            if is_test_path(rel):
                continue
            ctx.check_cancelled()
            dead = find_dead_js_imports(ws, path)
            if not dead:
                continue
            js_dead += len(dead)
            before = ws.read_text(path)
            diff = unified_diff(rel, before, fix_unused_requires(before))
            names = sorted({n for d in dead for n in d.names})
            result.findings.append(FindingDraft(
                rule_id="health:dead-imports", category="code_health", severity="low",
                title=f"{len(dead)} unused import(s) in {rel}",
                description="Unused: " + ", ".join(names[:12]),
                target=rel, location={"line": dead[0].line},
                evidence={"imports": [{"line": d.line, "names": d.names, "statement": d.text} for d in dead[:10]],
                          "detector": "lexically checked scalar require; any other name occurrence counts as used"},
                recommendation="Remove unused bindings while retaining the require calls.", confidence="high",
                fingerprint_key=f"deadimp|{rel}",
                proposal=ProposalDraft(
                    kind="refactor", title=f"Remove {len(dead)} unused import(s) from {rel}",
                    summary="Replaces unused scalar const/let require bindings with the same require calls, preserving "
                            "module evaluation and call order. ESM imports and destructuring are not rewritten.",
                    diff=diff, files=[rel]) if diff.strip() else None))

        cc_values = [f.complexity for f in functions] or [0]
        mi_values = [m.maintainability for m in modules if m.maintainability is not None]
        # Duplication scans all source languages, so its denominator must include them too.
        other_sloc = sum(sum(bool(line.strip()) for line in ws.read_text(path).splitlines())
                         for path in ws.iter_files(CODE_EXTS - {".py"}, max_bytes=300_000)
                         if not is_test_path(ws.rel(path)))
        total_sloc = sum(m.sloc for m in modules) + other_sloc
        denominator = max(total_sloc, 1)
        dup_lines = min(total_sloc, sum(d.lines * (len(d.occurrences) - 1) for d in dups))
        hotspots = sorted(({"file": m.file, "churn": hot.get(m.file, 0),
                            "max_complexity": max((f.complexity for f in m.functions), default=0),
                            "score": hot.get(m.file, 0) * max((f.complexity for f in m.functions), default=0)}
                           for m in modules), key=lambda h: -cast(int, h["score"]))[:10]
        health = max(0.0, min(100.0, 100 - max(0, statistics.fmean(cc_values) - 1) * 6
                              - (len(lint) + js_dead) / denominator * 400 - dup_lines / denominator * 100))
        result.metrics = {
            "python_modules": len(modules), "functions": len(functions), "sloc": total_sloc,
            "avg_complexity": round(statistics.fmean(cc_values), 2), "max_complexity": max(cc_values),
            "avg_maintainability": round(statistics.fmean(mi_values), 1) if mi_values else None,
            "lint_issues": len(lint), "lint_by_rule": dict(Counter(v["code"] for v in lint).most_common(15)),
            "dead_imports": js_dead,
            "javascript_modules": len(js_sources),
            "score_basis": "Python complexity/lint, source duplication, and unused JavaScript require bindings",
            "js_aggregation_modules_refactored": len(aggregation.occurrences) if aggregation else 0,
            "duplicate_blocks": len(dups), "duplication_pct": round(dup_lines / denominator * 100, 1),
            "hotspots": [h for h in hotspots if cast(int, h["score"]) > 0] or hotspots[:5],
            "health_score": round(health) if total_sloc else None,
            "complexity_distribution": dict(Counter(
                "A (1-5)" if c <= 5 else "B (6-10)" if c <= 10 else "C (11-20)" if c <= 20 else "D (21-30)"
                if c <= 30 else "E/F (31+)" for c in cc_values)),
        }
        ctx.progress(1.0, "Code health analysis complete")
        return result
