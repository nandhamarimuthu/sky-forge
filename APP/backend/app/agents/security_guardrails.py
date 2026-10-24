"""Agent 6 — Security Guardrails & Validation.

Two roles:
1. A scanning agent: secrets, dangerous code patterns, insecure IaC/Docker/CI configuration, prompt-injection bait.
2. A deterministic policy engine (`PolicyEngine`) that validates *every* proposed change from *every* agent before
   it can be approved or applied. Enforcement never depends on an LLM. All checks fail closed.
"""

from __future__ import annotations

import ast
import json
import math
import re
import shutil
import subprocess
import tempfile
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.adapters.repository.git_repo import RepoWorkspace, run_git
from app.adapters.scanners.code_metrics import is_test_path
from app.adapters.scanners.manifests import unified_diff
from app.adapters.scanners.terraform import TfResource
from app.agents.base import AgentContext, BaseAgent
from app.core.security import SECRET_PATTERNS, PathEscapeError, safe_join
from app.schemas.agents import AgentResult, FindingDraft, ProposalDraft

POLICY_VERSION = "2026.10"

# ---------------------------------------------------------------- code rules


@dataclass(frozen=True)
class CodeRule:
    id: str
    severity: str
    title: str
    pattern: re.Pattern[str]
    exts: tuple[str, ...]
    recommendation: str
    exclude: re.Pattern[str] | None = None


CODE_RULES: list[CodeRule] = [
    CodeRule("py-eval", "high", "Use of eval()/exec() on dynamic input", re.compile(r"(?<![.\w])(eval|exec)\(\s*(?!['\"])"),
             (".py",), "Replace with ast.literal_eval or explicit parsing."),
    CodeRule("py-shell-true", "high", "subprocess call with shell=True", re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"),
             (".py",), "Pass an argument list and shell=False."),
    CodeRule("py-os-system", "medium", "os.system / os.popen command execution", re.compile(r"\bos\.(system|popen)\("),
             (".py",), "Use subprocess.run([...], shell=False) with validated arguments."),
    CodeRule("py-pickle", "medium", "Unsafe deserialisation with pickle", re.compile(r"\b(c?pickle)\.loads?\("),
             (".py",), "Never unpickle untrusted data; use JSON or signed payloads."),
    CodeRule("py-yaml-load", "high", "yaml.load without a safe loader", re.compile(r"\byaml\.load\((?![^)]*SafeLoader)"),
             (".py",), "Use yaml.safe_load()."),
    CodeRule("py-tls-verify-off", "medium", "TLS certificate verification disabled",
             re.compile(r"verify\s*=\s*False"), (".py",), "Remove verify=False; trust a CA bundle instead."),
    CodeRule("py-sql-format", "high", "SQL built with string formatting (injection risk)",
             re.compile(r"(?i)\.execute\(\s*(f['\"]|['\"][^'\"]*\b(select|insert|update|delete)\b[^'\"]*['\"]\s*(%|\+|\.format))"),
             (".py",), "Use parameterised queries (cursor.execute(sql, params))."),
    CodeRule("py-flask-debug", "medium", "Flask/Werkzeug debug mode enabled", re.compile(r"\.run\([^)]*debug\s*=\s*True"),
             (".py",), "Disable debug in code; drive it from environment for local dev only."),
    CodeRule("py-weak-hash", "low", "Weak hash algorithm (MD5/SHA1)",
             re.compile(r"hashlib\.(md5|sha1)\((?![^)]*usedforsecurity\s*=\s*False)"),
             (".py",), "Use SHA-256+ (or bcrypt/argon2 for passwords)."),
    CodeRule("py-bind-all", "low", "Service binds to all interfaces", re.compile(r"host\s*=\s*['\"]0\.0\.0\.0['\"]"),
             (".py",), "Bind to localhost unless the service must be exposed."),
    CodeRule("js-eval", "high", "Use of eval()/new Function()", re.compile(r"(?<![.\w])eval\(|new Function\("),
             (".js", ".ts", ".jsx", ".tsx"), "Avoid dynamic code evaluation."),
    CodeRule("js-child-exec", "high", "child_process.exec with dynamic input",
             re.compile(r"child_process.*\.exec\(|\bexec\(\s*[`'\"].*\$\{"),
             (".js", ".ts"), "Use execFile/spawn with an argument array."),
    CodeRule("js-inner-html", "medium", "Assignment to innerHTML (XSS risk)",
             re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML"),
             (".js", ".ts", ".jsx", ".tsx"), "Use textContent or a sanitiser such as DOMPurify."),
    CodeRule("js-sql-concat", "high", "SQL built with string concatenation",
             re.compile(r"(?i)(query|execute)\(\s*[`'\"][^`'\"]*\b(select|insert|update|delete)\b[^`'\"]*[`'\"]\s*\+|\$\{[^}]+\}[^`]*\b(from|where)\b"),
             (".js", ".ts"), "Use parameterised queries."),
]

INJECTION_BAIT = re.compile(r"(?i)(ignore (all )?(previous|prior|above) instructions|disregard (the )?system prompt|"
                            r"you are now (a|an) |act as (a|an) (unfiltered|jailbroken)|exfiltrate|"
                            r"print (your|the) (system prompt|secrets|api key))")
DANGEROUS_ADDED = [
    ("destructive-shell", re.compile(r"rm\s+-rf\s+[/~]|mkfs|dd\s+if=|:\(\)\s*\{")),
    ("remote-exec", re.compile(r"(curl|wget)[^|\n]*\|\s*(ba|z)?sh")),
    ("chmod-777", re.compile(r"chmod\s+(-R\s+)?777")),
    ("dynamic-exec", re.compile(r"(?<![.\w])(eval|exec)\(|os\.system\(|subprocess\.|child_process|new Function\(")),
    ("open-ingress", re.compile(r"0\.0\.0\.0/0|::/0")),
    ("public-acl", re.compile(r"public-read(-write)?")),
    ("network-call", re.compile(r"\b(requests|httpx|urllib\.request|socket)\.\w+\(|fetch\(['\"]https?://")),
    ("env-exfil", re.compile(r"os\.environ\b(?!\.get\(['\"][A-Z0-9_]+['\"])|process\.env\b(?!\.[A-Z0-9_]+)")),
]
PROTECTED_PATHS = re.compile(r"(^|/)(\.git|\.github/workflows|\.gitlab-ci\.yml|Jenkinsfile|\.env[^/]*|.*\.pem|.*\.key|"
                             r"id_rsa[^/]*|\.npmrc|\.pypirc)$|(^|/)\.git/")
MANIFESTS = {"requirements.txt", "pyproject.toml", "package.json", "go.mod", "requirements-dev.txt",
             "requirements-test.txt", "requirements_dev.txt", "test-requirements.txt"}
KIND_RULES: dict[str, dict[str, Any]] = {
    "dependency_upgrade": {"exts": None, "new_files": False},
    "test_addition": {"exts": {".py"}, "new_files": True, "dir": re.compile(r"^(tests?|skyforge_tests)/")},
    "functional_test": {"exts": {".py", ".js", ".ts"}, "new_files": True,
                        "dir": re.compile(r"^(tests?|skyforge_tests)/")},
    "refactor": {"exts": {".py"}, "new_files": False},
    "config_fix": {"exts": {".py", ".js", ".ts", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini", ".tf"},
                   "new_files": False},
    "iac_change": {"exts": {".tf"}, "new_files": False},
    "advisory": {"exts": set(), "new_files": False},
}
MAX_CHANGED_LINES = 2000
MAX_FILES = 20


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def scan_secrets(text: str) -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue
        for name, pattern in SECRET_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue
            if name == "generic_secret_assignment":
                value = m.group(2)
                if (shannon_entropy(value) < 3.0 or re.fullmatch(r"(?i)(changeme|password|secret|example|test|"
                                                                 r"dummy|xxx+|\*+|your[_-].*|<.*>|\$\{.*\})", value)):
                    continue
            hits.append((name, lineno, line.strip()[:20] + "…"))
    return hits


def scan_generated_code(code: str) -> list[str]:
    """Policy check for agent-generated code (tests): returns violations; empty list means acceptable."""
    violations = [name for name, pat in DANGEROUS_ADDED if pat.search(code) and name not in ("open-ingress", "public-acl")]
    if scan_secrets(code):
        violations.append("secret-material")
    if re.search(r"(?m)^\s*(import|from)\s+(os|subprocess|socket|shutil|requests|httpx|urllib)\b", code):
        violations.append("forbidden-import")
    if INJECTION_BAIT.search(code):
        violations.append("prompt-injection-text")
    return violations


def detect_prompt_injection(text: str) -> list[str]:
    return [m.group(0) for m in INJECTION_BAIT.finditer(text)][:5]


# ---------------------------------------------------------------- diff parsing


def parse_diff_files(diff: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for line in diff.splitlines():
        if line.startswith("--- "):
            cur = {"old": line[4:].strip(), "new": None, "added": [], "removed": []}
            files.append(cur)
        elif line.startswith("+++ ") and cur is not None:
            cur["new"] = line[4:].strip()
        elif cur is not None and line.startswith("+") and not line.startswith("+++"):
            cur["added"].append(line[1:])
        elif cur is not None and line.startswith("-") and not line.startswith("---"):
            cur["removed"].append(line[1:])
    for f in files:
        new = f["new"] or ""
        f["path"] = new[2:] if new.startswith("b/") else new
        f["is_new"] = f["old"] in ("/dev/null", "a//dev/null")
    return files


def _check(name: str, passed: bool, detail: str = "") -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


class PolicyEngine:
    """Deterministic validation of proposed changes. `validate` never raises; it fails closed."""

    def __init__(self, workspace: RepoWorkspace):
        self.ws = workspace

    def validate(self, proposal: ProposalDraft | Any) -> dict[str, Any]:
        try:
            return self._validate(proposal)
        except Exception as exc:  # noqa: BLE001 - fail closed on any unexpected error
            return {"passed": False, "policy_version": POLICY_VERSION,
                    "checks": [_check("engine", False, f"Validation error: {type(exc).__name__}: {exc}"[:300])],
                    "requires_human_approval": True}

    def _validate(self, p: Any) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        kind = p.kind
        rules = KIND_RULES.get(kind)
        checks.append(_check("known_change_type", rules is not None, kind))
        if kind == "advisory" or not p.diff.strip():
            ok = kind == "advisory"
            checks.append(_check("has_patch", ok, "Advisory only — nothing to apply" if ok else "Empty diff"))
            return self._result(checks, p)
        files = parse_diff_files(p.diff)
        paths = [f["path"] for f in files]
        checks.append(_check("diff_parses", bool(files), f"{len(files)} file(s)"))
        checks.append(_check("declared_files_match", sorted(set(paths)) == sorted(set(p.files)),
                             f"diff={sorted(set(paths))} declared={sorted(set(p.files))}"))
        changed = sum(len(f["added"]) + len(f["removed"]) for f in files)
        checks.append(_check("size_limits", len(files) <= MAX_FILES and changed <= MAX_CHANGED_LINES,
                             f"{len(files)} files, {changed} changed lines"))
        bad_paths = []
        for f in files:
            path = f["path"]
            try:
                target = safe_join(self.ws.root, path)
            except PathEscapeError:
                bad_paths.append(f"{path} (escapes workspace)")
                continue
            if PROTECTED_PATHS.search(path):
                bad_paths.append(f"{path} (protected path)")
            if rules:
                exts = rules["exts"]
                if kind == "dependency_upgrade" and Path(path).name not in MANIFESTS:
                    bad_paths.append(f"{path} (not a dependency manifest)")
                elif exts is not None and Path(path).suffix not in exts:
                    bad_paths.append(f"{path} (extension not allowed for {kind})")
                if rules.get("dir") and not rules["dir"].search(path):
                    bad_paths.append(f"{path} (generated tests must live under tests/)")
                if f["is_new"] and not rules["new_files"]:
                    bad_paths.append(f"{path} (new files not allowed for {kind})")
                if not f["is_new"] and not target.exists():
                    bad_paths.append(f"{path} (does not exist)")
                if f["is_new"] and target.exists():
                    bad_paths.append(f"{path} (would overwrite an existing file)")
        checks.append(_check("allowed_paths", not bad_paths, "; ".join(bad_paths) or "all paths in scope"))

        added = "\n".join(line for f in files for line in f["added"])
        removed = "\n".join(line for f in files for line in f["removed"])
        hits = []
        for name, pat in DANGEROUS_ADDED:
            if pat.search(added) and not pat.search(removed):
                if kind in ("refactor", "dependency_upgrade", "iac_change", "config_fix") or name != "env-exfil":
                    hits.append(name)
        if kind == "config_fix":
            hits = [h for h in hits if h != "env-exfil"]
        checks.append(_check("no_dangerous_content", not hits, ", ".join(sorted(set(hits))) or "clean"))
        secrets = scan_secrets(added)
        checks.append(_check("no_secrets_introduced", not secrets, f"{len(secrets)} secret pattern(s)" if secrets else
                             "clean"))
        checks.append(_check("no_prompt_injection_text", not detect_prompt_injection(added), "clean"))
        if kind == "dependency_upgrade":
            only_versions = all(
                re.sub(r"[0-9][0-9A-Za-z.\-+]*", "V", a) == re.sub(r"[0-9][0-9A-Za-z.\-+]*", "V", r)
                for f in files for a, r in zip(f["added"], f["removed"], strict=False)
            ) and all(len(f["added"]) == len(f["removed"]) for f in files)
            checks.append(_check("version_only_change", only_versions,
                                 "only version tokens changed" if only_versions else "non-version edits detected"))
        if kind == "refactor":
            checks.append(_check("no_new_imports_of_risky_modules",
                                 not re.search(r"(?m)^\s*(import|from)\s+(os|subprocess|socket|pickle)\b", added),
                                 "clean"))
        apply_ok, apply_detail, syntax = self._apply_and_parse(p.diff, files)
        checks.append(_check("applies_cleanly", apply_ok, apply_detail))
        checks.append(_check("syntax_valid", apply_ok and all(s[1] for s in syntax),
                             "; ".join(f"{f}: {'ok' if ok else msg}" for f, ok, msg in syntax)[:500] or "n/a"))
        return self._result(checks, p)

    @staticmethod
    def _result(checks: list[dict[str, Any]], p: Any) -> dict[str, Any]:
        return {"passed": all(c["passed"] for c in checks), "policy_version": POLICY_VERSION, "checks": checks,
                "requires_human_approval": True, "breaking_change": bool(getattr(p, "breaking", False))}

    def _apply_and_parse(self, diff: str, files: list[dict[str, Any]]) -> tuple[bool, str, list[tuple[str, bool, str]]]:
        tmp = Path(tempfile.mkdtemp(prefix="skyforge-policy-"))
        try:
            for f in files:
                if f["is_new"]:
                    continue
                src = safe_join(self.ws.root, f["path"])
                dst = tmp / f["path"]
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
            run_git(["init", "-q"], cwd=tmp)
            (tmp / ".sf.patch").write_text(diff if diff.endswith("\n") else diff + "\n", encoding="utf-8")
            try:
                run_git(["apply", "--check", "--whitespace=nowarn", ".sf.patch"], cwd=tmp)
                run_git(["apply", "--whitespace=nowarn", ".sf.patch"], cwd=tmp)
            except Exception as exc:  # noqa: BLE001
                return False, str(exc)[:300], []
            results = []
            for f in files:
                path = tmp / f["path"]
                results.append((f["path"], *syntax_check(path)))
            return True, "git apply --check succeeded", results
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def syntax_check(path: Path) -> tuple[bool, str]:
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".py":
            ast.parse(text)
        elif path.suffix == ".json":
            json.loads(text)
        elif path.suffix == ".toml":
            tomllib.loads(text)
        elif path.suffix == ".tf" and shutil.which("terraform"):
            r = subprocess.run(["terraform", "fmt", "-check=false", "-write=false", "-"], input=text,
                               capture_output=True, text=True, timeout=30, check=False)
            if r.returncode != 0:
                return False, r.stderr.strip()[:200]
        elif path.suffix == ".tf":
            if text.count("{") != text.count("}"):
                return False, "unbalanced braces"
        return True, "ok"
    except (SyntaxError, ValueError, tomllib.TOMLDecodeError, OSError) as exc:
        return False, f"{type(exc).__name__}: {exc}"[:200]


# ---------------------------------------------------------------- remediation codemods


def _codemod_line(ws: RepoWorkspace, rel: str, line_no: int, transform: Any) -> str | None:
    text = ws.read_text(rel)
    lines = text.splitlines(keepends=True)
    if not 0 < line_no <= len(lines):
        return None
    new = transform(lines[line_no - 1])
    if not new or new == lines[line_no - 1]:
        return None
    lines[line_no - 1] = new
    return unified_diff(rel, text, "".join(lines))


def code_fix(ws: RepoWorkspace, rule_id: str, rel: str, line_no: int) -> ProposalDraft | None:
    fixes = {
        "py-yaml-load": (lambda ln: re.sub(r"\byaml\.load\(", "yaml.safe_load(", ln)
                         .replace(", Loader=yaml.Loader", "").replace(", Loader=yaml.FullLoader", ""),
                         "Use yaml.safe_load"),
        "py-tls-verify-off": (lambda ln: re.sub(r",\s*verify\s*=\s*False", "", ln), "Re-enable TLS verification"),
        "py-flask-debug": (lambda ln: re.sub(r"debug\s*=\s*True", "debug=False", ln), "Disable debug mode"),
        "py-shell-true": (lambda ln: ln if "[" not in ln else re.sub(r"shell\s*=\s*True", "shell=False", ln),
                          "Disable shell=True"),
    }
    if rule_id not in fixes:
        return None
    fn, title = fixes[rule_id]
    diff = _codemod_line(ws, rel, line_no, fn)
    if not diff:
        return None
    return ProposalDraft(kind="config_fix", title=f"{title} in {rel}:{line_no}",
                         summary="Minimal single-line change generated by a deterministic codemod.", diff=diff,
                         files=[rel])


def secret_fix(ws: RepoWorkspace, rel: str, line_no: int) -> ProposalDraft | None:
    if not rel.endswith(".py"):
        return None
    text = ws.read_text(rel)
    lines = text.splitlines(keepends=True)
    if not 0 < line_no <= len(lines):
        return None
    m = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"][^'\"]+['\"]\s*(#.*)?$", lines[line_no - 1].rstrip("\n"))
    if not m:
        return None
    indent, var = m.group(1), m.group(2)
    lines[line_no - 1] = f'{indent}{var} = os.environ.get("{var.upper()}", "")\n'
    if not re.search(r"(?m)^import os\b|^from os import|^import os,", text):
        insert_at = 0
        for i, ln in enumerate(lines):
            if ln.startswith(("import ", "from ")):
                insert_at = i
                break
            if ln.strip() and not ln.startswith(("#", '"""', "'''")) and i > 0:
                break
        lines.insert(insert_at, "import os\n")
    diff = unified_diff(rel, text, "".join(lines))
    return ProposalDraft(kind="config_fix", title=f"Move hard-coded secret {var} to environment",
                         summary=f"Reads {var.upper()} from the environment. The exposed value must also be ROTATED — "
                                 "removing it from code does not remove it from git history.", diff=diff, files=[rel],
                         codemod={"type": "secret_env", "file": rel, "line": line_no})


def iac_fix(ws: RepoWorkspace, res: TfResource, key: str, old_pattern: str, replacement: str,
            title: str) -> ProposalDraft | None:
    if key not in res.attrs:
        return None
    _, line_no = res.attrs[key]
    diff = _codemod_line(ws, res.file, line_no, lambda ln: re.sub(old_pattern, replacement, ln, count=1))
    if not diff:
        return None
    return ProposalDraft(kind="iac_change", title=title, summary="Terraform change; apply through your normal "
                                                                 "plan/review pipeline.", diff=diff, files=[res.file])


# ---------------------------------------------------------------- scanning agent


class SecurityGuardrailsAgent(BaseAgent):
    id = "guardrails"
    name = "Security Guardrails"
    code = "Security Guardrails"
    description = ("Deterministic policy engine: secrets, injection risks, insecure IaC/CI, and validation of every "
                   "proposed change before approval.")
    allowed_tools = frozenset({"repo.read", "terraform.parse"})

    def run(self, ctx: AgentContext) -> AgentResult:
        ws: RepoWorkspace = ctx.tool("repo.read")
        result = AgentResult(agent_id="guardrails", tools_used=["secret-scanner", "pattern-rules", "iac-policy",
                                                               "ci-policy"])
        counts: Counter[str] = Counter()
        files_scanned = 0
        for n, path in enumerate(ws.iter_files(max_bytes=500_000)):
            if n % 200 == 0:
                ctx.check_cancelled()
            rel = ws.rel(path)
            if path.suffix.lower() in {".png", ".jpg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2",
                                       ".ttf", ".lock", ".svg", ".min.js", ".map"} or rel.endswith(".min.js"):
                continue
            try:
                text = ws.read_text(path)
            except Exception:  # noqa: BLE001, S112 - unreadable/binary files are skipped by design
                continue
            if "\x00" in text[:1000]:
                continue
            files_scanned += 1
            in_tests = is_test_path(rel)
            for name, line_no, _preview in scan_secrets(text):
                counts["secret"] += 1
                sev = "low" if in_tests else ("critical" if name in ("private_key", "aws_access_key_id",
                                                                      "aws_secret_access_key", "github_token",
                                                                      "github_pat", "stripe_key") else "high")
                result.findings.append(FindingDraft(
                    rule_id=f"secret:{name}", category="secret", severity=sev,  # type: ignore[arg-type]
                    title=f"Possible {name.replace('_', ' ')} committed in {rel}",
                    description="Secret-like material in source control. Value redacted in SkyForge.",
                    target=rel, location={"line": line_no},
                    evidence={"detector": name, "preview": "[REDACTED]", "in_test_code": in_tests},
                    recommendation="Rotate the credential, remove it from the code and history, load it from a "
                                   "secret manager/environment.", confidence="medium" if name.startswith("generic")
                    else "high", fingerprint_key=f"secret|{rel}|{line_no}|{name}",
                    proposal=None if in_tests else secret_fix(ws, rel, line_no)))
            for rule in CODE_RULES:
                if path.suffix not in rule.exts:
                    continue
                for line_no, line in enumerate(text.splitlines(), 1):
                    s = line.strip()
                    if s.startswith(("#", "//", "*")) or not rule.pattern.search(line):
                        continue
                    counts[rule.id] += 1
                    result.findings.append(FindingDraft(
                        rule_id=f"code:{rule.id}", category="security_policy",
                        severity="low" if in_tests else rule.severity,  # type: ignore[arg-type]
                        title=f"{rule.title} — {rel}:{line_no}", target=rel, location={"line": line_no},
                        evidence={"snippet": s[:200], "rule": rule.id, "in_test_code": in_tests},
                        recommendation=rule.recommendation, confidence="medium",
                        fingerprint_key=f"code|{rule.id}|{rel}|{s[:80]}",
                        proposal=None if in_tests else code_fix(ws, rule.id, rel, line_no)))
                    if counts[rule.id] > 60:
                        break
            if INJECTION_BAIT.search(text):
                result.findings.append(FindingDraft(
                    rule_id="llm:prompt-injection-bait", category="security_policy", severity="info",
                    title=f"Prompt-injection style text in {rel}", target=rel,
                    evidence={"matches": detect_prompt_injection(text)},
                    recommendation="Content is treated as untrusted data by SkyForge agents; review intent.",
                    confidence="low", fingerprint_key=f"inj|{rel}"))
            if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
                self._dockerfile(result, rel, text)
            if rel.startswith(".github/workflows/") and path.suffix in (".yml", ".yaml"):
                self._workflow(result, rel, text)
        ctx.progress(0.7, f"Scanned {files_scanned} files")
        tf = ctx.tool("terraform.parse")(ws)
        self._terraform(ws, result, tf)
        result.metrics = {"files_scanned": files_scanned, "terraform_resources": len(tf),
                          "by_rule": dict(counts.most_common(20)), "policy_version": POLICY_VERSION}
        ctx.progress(1.0, "Guardrail scan complete")
        return result

    @staticmethod
    def _dockerfile(result: AgentResult, rel: str, text: str) -> None:
        if not re.search(r"(?mi)^\s*USER\s+(?!root\b)\S+", text):
            result.findings.append(FindingDraft(
                rule_id="docker:runs-as-root", category="security_policy", severity="medium",
                title=f"{rel} runs the container as root", target=rel,
                recommendation="Add a non-root USER instruction.", confidence="high",
                fingerprint_key=f"docker|root|{rel}"))
        for i, line in enumerate(text.splitlines(), 1):
            if re.match(r"(?i)^\s*FROM\s+\S+:latest\b|^\s*FROM\s+[^:@\s]+\s*$", line):
                result.findings.append(FindingDraft(
                    rule_id="docker:unpinned-base", category="security_policy", severity="low",
                    title=f"Unpinned base image in {rel}:{i}", target=rel, location={"line": i},
                    evidence={"line": line.strip()}, recommendation="Pin the base image to a version or digest.",
                    confidence="high", fingerprint_key=f"docker|latest|{rel}|{i}"))
            if re.search(r"(curl|wget)[^|]*\|\s*(ba)?sh", line):
                result.findings.append(FindingDraft(
                    rule_id="docker:curl-pipe-shell", category="security_policy", severity="medium",
                    title=f"Remote script piped to shell in {rel}:{i}", target=rel, location={"line": i},
                    recommendation="Download, verify checksum, then execute.", confidence="high",
                    fingerprint_key=f"docker|curlsh|{rel}|{i}"))

    @staticmethod
    def _workflow(result: AgentResult, rel: str, text: str) -> None:
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit)\.[\w.]*"
                         r"(title|body|message|name|ref|label)|head_ref)", line):
                result.findings.append(FindingDraft(
                    rule_id="ci:expression-injection", category="security_policy", severity="high",
                    title=f"Untrusted GitHub context interpolated in workflow {rel}:{i}", target=rel,
                    location={"line": i}, evidence={"line": line.strip()[:200]},
                    recommendation="Pass the value through an environment variable and quote it.", confidence="high",
                    fingerprint_key=f"ci|inj|{rel}|{i}"))
        if "pull_request_target" in text and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text):
            result.findings.append(FindingDraft(
                rule_id="ci:pwn-request", category="security_policy", severity="critical",
                title=f"pull_request_target checks out untrusted PR code in {rel}", target=rel,
                recommendation="Never check out PR head code in pull_request_target workflows with secrets.",
                confidence="high", fingerprint_key=f"ci|pwn|{rel}"))

    @staticmethod
    def _terraform(ws: RepoWorkspace, result: AgentResult, tf: list[TfResource]) -> None:
        def add(res: TfResource, rule: str, sev: str, title: str, rec: str, line: int | None = None,
                proposal: ProposalDraft | None = None) -> None:
            result.findings.append(FindingDraft(
                rule_id=f"iac:{rule}", category="iac", severity=sev,  # type: ignore[arg-type]
                title=f"{title} ({res.address})", target=res.file, location={"line": line or res.start_line},
                evidence={"resource": res.address, "attributes": {k: v[0] for k, v in list(res.attrs.items())[:15]}},
                recommendation=rec, confidence="high", fingerprint_key=f"iac|{rule}|{res.address}",
                proposal=proposal))

        for r in tf:
            body = r.body
            if r.type in ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"):
                for m in re.finditer(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]|cidr_ipv4\s*=\s*"0\.0\.0\.0/0"', body):
                    ctx_text = body[max(0, m.start() - 300):m.end() + 50]
                    if "egress" in ctx_text.split("ingress")[-1][:60] and "ingress" not in ctx_text:
                        continue
                    port = re.search(r"from_port\s*=\s*(\d+)", ctx_text)
                    sensitive = port and port.group(1) in ("22", "3389", "3306", "5432", "6379", "27017", "0")
                    line = r.start_line + body[:m.start()].count("\n")
                    add(r, "open-ingress", "critical" if sensitive else "high",
                        f"Ingress open to the internet{f' on port {port.group(1)}' if port else ''}",
                        "Restrict to known CIDRs or use SSM Session Manager instead of public SSH.", line)
            if r.type in ("aws_s3_bucket", "aws_s3_bucket_acl") and re.search(r'acl\s*=\s*"public-read', body):
                add(r, "s3-public-acl", "high", "S3 bucket has a public ACL", "Use private ACL + Block Public Access.",
                    proposal=iac_fix(ws, r, "acl", r'"public-read(-write)?"', '"private"',
                                     f"Make {r.address} private"))
            if r.type == "aws_s3_bucket_public_access_block" and re.search(r"block_public_acls\s*=\s*false", body):
                add(r, "s3-public-access", "high", "S3 public access block disabled", "Set all four flags to true.")
            if r.type in ("aws_db_instance", "aws_rds_cluster"):
                if r.value("storage_encrypted") in (None, "false"):
                    add(r, "rds-unencrypted", "high", "RDS storage not encrypted", "Set storage_encrypted = true.",
                        proposal=iac_fix(ws, r, "storage_encrypted", r"false", "true",
                                         f"Encrypt storage for {r.address}") if r.value("storage_encrypted") == "false"
                        else None)
                if r.value("publicly_accessible") == "true":
                    add(r, "rds-public", "critical", "RDS instance publicly accessible",
                        "Set publicly_accessible = false and use private subnets.",
                        proposal=iac_fix(ws, r, "publicly_accessible", r"true", "false",
                                         f"Make {r.address} private"))
            if r.type == "aws_ebs_volume" and r.value("encrypted") in (None, "false"):
                add(r, "ebs-unencrypted", "medium", "EBS volume not encrypted", "Set encrypted = true.")
            if r.type in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy") and \
                    re.search(r'"?Action"?\s*[:=]\s*"\*"|"Action"\s*:\s*\[\s*"\*"\s*\]', body) and \
                    re.search(r'"?Resource"?\s*[:=]\s*"\*"', body):
                add(r, "iam-wildcard", "critical", "IAM policy grants *:* permissions", "Apply least privilege.")
            if r.type == "aws_cloudtrail" and r.value("enable_log_file_validation") in (None, "false"):
                add(r, "cloudtrail-validation", "medium", "CloudTrail log validation disabled",
                    "Set enable_log_file_validation = true.")
            if r.type == "aws_instance" and r.value("associate_public_ip_address") == "true":
                add(r, "ec2-public-ip", "medium", "EC2 instance gets a public IP", "Place behind a load balancer/NAT.")
