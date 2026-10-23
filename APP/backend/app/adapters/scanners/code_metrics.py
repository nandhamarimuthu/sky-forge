"""Static code analysis helpers: Ruff, Radon, duplication detection and Python AST inventories.

None of these execute repository code.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.repository.git_repo import RepoWorkspace

CODE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|e2e)(/|$)|(^|/)test_[^/]+\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$")


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH.search(rel))


def ruff_binary() -> str | None:
    candidate = Path(sys.executable).parent / "ruff"
    if candidate.exists():
        return str(candidate)
    return shutil.which("ruff")


RUFF_RULES = "E,F,W,B,C90,SIM,UP,PL"
RUFF_SAFE_FIX_RULES = "F401,F541,F632,E711,E712,E713,E714,UP,SIM101,SIM103,SIM108,SIM118,W291,W293,C401,C403,C408"


def run_ruff(root: Path, timeout: int = 120) -> list[dict]:
    exe = ruff_binary()
    if not exe:
        return []
    res = subprocess.run([exe, "check", "--isolated", "--no-cache", "--select", RUFF_RULES, "--ignore", "E501",
                          "--output-format", "json", "--exit-zero", "."], cwd=root, capture_output=True, text=True,
                         timeout=timeout, check=False)
    try:
        return json.loads(res.stdout or "[]")
    except json.JSONDecodeError:
        return []


def ruff_fix_diff(root: Path, files: list[str], timeout: int = 120) -> str:
    """Return the unified diff Ruff *would* apply for safe, behaviour-preserving fixes (files untouched)."""
    exe = ruff_binary()
    if not exe or not files:
        return ""
    res = subprocess.run([exe, "check", "--isolated", "--no-cache", "--select", RUFF_SAFE_FIX_RULES,
                          "--fix", "--diff", "--exit-zero", "--", *files], cwd=root, capture_output=True, text=True,
                         timeout=timeout, check=False)
    return _normalize_ruff_diff(res.stdout)


def _normalize_ruff_diff(diff: str) -> str:
    out = []
    for line in diff.splitlines(keepends=True):
        if line.startswith("--- ") and not line.startswith("--- a/"):
            line = "--- a/" + line[4:].strip().lstrip("./") + "\n"
        elif line.startswith("+++ ") and not line.startswith("+++ b/"):
            line = "+++ b/" + line[4:].strip().lstrip("./") + "\n"
        out.append(line)
    text = "".join(out)
    if "\n@@ " not in text and not text.startswith("@@ "):
        return ""  # e.g. "No errors would be fixed (…--unsafe-fixes)" — nothing to propose
    return "\n".join(ln for ln in text.splitlines() if not ln.startswith(("Would fix", "No errors would be fixed"))
                     ) + "\n"


@dataclass
class FunctionInfo:
    name: str
    qualname: str
    file: str
    line: int
    end_line: int
    complexity: int
    args: list[dict]
    is_method: bool
    is_async: bool
    decorators: list[str]
    returns: str | None
    docstring: str | None
    class_name: str | None = None


@dataclass
class ModuleMetrics:
    file: str
    loc: int
    sloc: int
    maintainability: float | None
    functions: list[FunctionInfo] = field(default_factory=list)
    parse_error: str | None = None


def _ann(node: ast.expr | None) -> str | None:
    return ast.unparse(node) if node is not None else None


def _complexity_map(source: str) -> dict[tuple[str, int], int]:
    try:
        from radon.complexity import cc_visit
    except ImportError:  # pragma: no cover
        return {}
    out: dict[tuple[str, int], int] = {}
    try:
        for block in cc_visit(source):
            out[(block.name, block.lineno)] = block.complexity
            for m in getattr(block, "methods", []) or []:
                out[(m.name, m.lineno)] = m.complexity
    except (SyntaxError, ValueError):
        pass
    return out


def analyse_python_module(ws: RepoWorkspace, path: Path) -> ModuleMetrics:
    rel = ws.rel(path)
    source = ws.read_text(path)
    lines = source.splitlines()
    sloc = sum(1 for ln in lines if ln.strip() and not ln.strip().startswith("#"))
    mi: float | None = None
    try:
        from radon.metrics import mi_visit

        mi = round(float(mi_visit(source, multi=True)), 1)
    except Exception:  # noqa: BLE001 - radon raises assorted errors on odd syntax
        mi = None
    metrics = ModuleMetrics(file=rel, loc=len(lines), sloc=sloc, maintainability=mi)
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        metrics.parse_error = f"{exc.msg} (line {exc.lineno})"
        return metrics
    cc = _complexity_map(source)

    def visit(body: list[ast.stmt], class_name: str | None) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, node.name)
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                args: list[dict[str, Any]] = []
                pos = node.args.posonlyargs + node.args.args
                defaults = [None] * (len(pos) - len(node.args.defaults)) + list(node.args.defaults)
                for a, d in zip(pos, defaults, strict=False):
                    args.append({"name": a.arg, "annotation": _ann(a.annotation),
                                 "default": ast.unparse(d) if d is not None else None})
                for a, d in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=False):
                    args.append({"name": a.arg, "annotation": _ann(a.annotation),
                                 "default": ast.unparse(d) if d is not None else None, "kwonly": True})
                if node.args.vararg:
                    args.append({"name": "*" + node.args.vararg.arg, "annotation": None, "default": "()"})
                if node.args.kwarg:
                    args.append({"name": "**" + node.args.kwarg.arg, "annotation": None, "default": "{}"})
                metrics.functions.append(FunctionInfo(
                    name=node.name, qualname=f"{class_name}.{node.name}" if class_name else node.name, file=rel,
                    line=node.lineno, end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    complexity=cc.get((node.name, node.lineno), 1), args=args, is_method=class_name is not None,
                    is_async=isinstance(node, ast.AsyncFunctionDef),
                    decorators=[ast.unparse(d) for d in node.decorator_list], returns=_ann(node.returns),
                    docstring=ast.get_docstring(node), class_name=class_name))

    visit(tree.body, None)
    return metrics


def module_name_for(rel: str) -> str:
    parts = rel[:-3].split("/") if rel.endswith(".py") else rel.split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if parts and parts[0] == "src":
        parts = parts[1:]
    return ".".join(parts)


@dataclass
class DuplicateBlock:
    hash: str
    lines: int
    occurrences: list[tuple[str, int]]


def find_duplicates(ws: RepoWorkspace, window: int = 8, max_files: int = 600) -> list[DuplicateBlock]:
    index: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for count, path in enumerate(ws.iter_files(CODE_EXTS, max_bytes=300_000)):
        if count >= max_files:
            break
        rel = ws.rel(path)
        if is_test_path(rel):
            continue
        raw = ws.read_text(path).splitlines()
        norm = [(i + 1, re.sub(r"\s+", " ", ln.strip())) for i, ln in enumerate(raw)]
        norm = [(i, ln) for i, ln in norm if ln and not ln.startswith(("#", "//", "import ", "from ", "}", "*"))
                and len(ln) > 3]
        for k in range(0, max(0, len(norm) - window + 1)):
            chunk = "\n".join(ln for _, ln in norm[k:k + window])
            h = hashlib.sha1(chunk.encode(), usedforsecurity=False).hexdigest()
            index[h].append((rel, norm[k][0]))
    blocks: list[DuplicateBlock] = []
    claimed: set[tuple[str, int]] = set()
    for h, occ in index.items():
        distinct: list[tuple[str, int]] = []
        for f, line in occ:
            if any(f == cf and abs(line - cl) < window for cf, cl in distinct):
                continue
            distinct.append((f, line))
        if len(distinct) < 2 or any(o in claimed for o in distinct):
            continue
        for f, line in distinct:
            for d in range(-window, window + 1):
                claimed.add((f, line + d))
        blocks.append(DuplicateBlock(hash=h[:12], lines=window, occurrences=distinct[:6]))
    return blocks


# ---------- Route discovery (FastAPI / Flask / Express / Django) ----------

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


@dataclass
class Route:
    framework: str
    method: str
    path: str
    file: str
    line: int
    handler: str
    app_var: str
    requires_auth: bool = False


def discover_python_routes(ws: RepoWorkspace, path: Path) -> tuple[list[Route], dict]:
    rel = ws.rel(path)
    try:
        tree = ast.parse(ws.read_text(path))
    except SyntaxError:
        return [], {}
    routes: list[Route] = []
    apps: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn = ast.unparse(node.value.func)
            for t in node.targets:
                if isinstance(t, ast.Name):
                    if fn.endswith("FastAPI"):
                        apps[t.id] = "fastapi"
                    elif fn.endswith("APIRouter"):
                        apps[t.id] = "fastapi-router"
                    elif fn.endswith("Flask"):
                        apps[t.id] = "flask"
                    elif fn.endswith("Blueprint"):
                        apps[t.id] = "flask-blueprint"
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        src_args = ast.unparse(node.args)
        auth = bool(re.search(r"(?i)(auth|token|current_user|login_required|security|depends\(.*user)", src_args))
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                continue
            owner = ast.unparse(dec.func.value)
            attr = dec.func.attr.lower()
            if owner not in apps:
                continue
            dec_src = ast.unparse(dec)
            if "login_required" in " ".join(ast.unparse(d) for d in node.decorator_list):
                auth = True
            path_arg = dec.args[0] if dec.args else None
            if not (isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str)):
                continue
            methods: list[str] = []
            if attr in HTTP_METHODS:
                methods = [attr.upper()]
            elif attr in ("route", "api_route"):
                m = re.search(r"methods\s*=\s*\[([^\]]*)\]", dec_src)
                methods = [x.strip(" '\"").upper() for x in m.group(1).split(",")] if m else ["GET"]
            for method in methods:
                routes.append(Route(apps[owner].split("-")[0], method, path_arg.value, rel, node.lineno, node.name,
                                    owner, auth))
    return routes, apps


_EXPRESS = re.compile(r"\b(app|router)\.(get|post|put|patch|delete)\(\s*['\"`]([^'\"`]+)['\"`]")


def discover_js_routes(ws: RepoWorkspace, path: Path) -> list[Route]:
    rel = ws.rel(path)
    out = []
    for i, line in enumerate(ws.read_text(path).splitlines(), 1):
        for m in _EXPRESS.finditer(line):
            auth = bool(re.search(r"(?i)(auth|isLoggedIn|ensureAuth|passport|jwt)", line))
            out.append(Route("express", m.group(2).upper(), m.group(3), rel, i, "", m.group(1), auth))
    return out
