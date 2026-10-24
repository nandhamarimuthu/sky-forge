"""Dependency manifest parsing and minimal, line-preserving upgrade patches."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.adapters.repository.git_repo import RepoWorkspace

GENERIC_ECOSYSTEMS = ("Maven", "RubyGems", "Packagist", "crates.io", "NuGet")

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(==|===|>=|~=)\s*([A-Za-z0-9.*+!\-]+)")
_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(==|>=|~=)\s*([A-Za-z0-9.*+!\-]+)")
_NPM_VER = re.compile(r"^\s*([\^~>=]*)\s*v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)\s*$")
_GO_REQ = re.compile(r"^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+\.[a-z]{2,}[a-zA-Z0-9.\-_/]*)\s+v([0-9][^\s]*)")


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str  # PyPI | npm | Go
    file: str
    line: int
    spec: str
    pinned: bool
    direct: bool = True
    extra: dict = field(default_factory=dict)


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(ws: RepoWorkspace, path: Path) -> list[Dependency]:
    out: list[Dependency] = []
    rel = ws.rel(path)
    for i, line in enumerate(ws.read_text(path).splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith(("-", "git+", "http")):
            continue
        m = _REQ_LINE.match(stripped)
        if m and "*" not in m.group(4):
            out.append(Dependency(m.group(1), m.group(4), "PyPI", rel, i, m.group(3), m.group(3) in ("==", "===")))
    return out


def _pyproject(ws: RepoWorkspace, path: Path) -> list[Dependency]:
    text = ws.read_text(path)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    rel = ws.rel(path)
    lines = text.splitlines()
    specs: list[str] = list(data.get("project", {}).get("dependencies", []) or [])
    for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
        specs.extend(group or [])
    out: list[Dependency] = []
    for spec in specs:
        m = _PEP508.match(spec)
        if not m:
            continue
        line_no = next((i for i, ln in enumerate(lines, 1) if spec in ln), 0)
        out.append(Dependency(m.group(1), m.group(4), "PyPI", rel, line_no, m.group(3), m.group(3) == "=="))
    poetry = data.get("tool", {}).get("poetry", {})
    for section in ("dependencies", "dev-dependencies"):
        for name, ver in (poetry.get(section, {}) or {}).items():
            if name.lower() == "python" or not isinstance(ver, str):
                continue
            mm = _NPM_VER.match(ver.replace("==", ""))
            if mm:
                line_no = next((i for i, ln in enumerate(lines, 1) if ln.strip().startswith(f"{name} ")), 0)
                out.append(Dependency(name, mm.group(2), "PyPI", rel, line_no, mm.group(1) or "==",
                                      not mm.group(1)))
    return out


def _package_json(ws: RepoWorkspace, path: Path) -> list[Dependency]:
    text = ws.read_text(path)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    rel = ws.rel(path)
    lines = text.splitlines()
    lock_versions: dict[str, str] = {}
    lock = path.with_name("package-lock.json")
    if lock.exists():
        try:
            lock_data = json.loads(ws.read_text(lock)) if lock.stat().st_size < ws.MAX_FILE_BYTES else {}
            for key, meta in (lock_data.get("packages") or {}).items():
                if key.startswith("node_modules/") and key.count("node_modules/") == 1 and "version" in meta:
                    lock_versions[key[len("node_modules/"):]] = meta["version"]
            for name, meta in (lock_data.get("dependencies") or {}).items():
                lock_versions.setdefault(name, meta.get("version", ""))
        except (json.JSONDecodeError, OSError):
            pass
    out: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            if not isinstance(ver, str):
                continue
            m = _NPM_VER.match(ver)
            locked = lock_versions.get(name)
            if not m and not locked:
                continue
            version = locked or (m.group(2) if m else "")
            prefix = m.group(1) if m else ""
            line_no = next((i for i, ln in enumerate(lines, 1) if f'"{name}"' in ln), 0)
            out.append(Dependency(name, version, "npm", rel, line_no, prefix, bool(locked) or not prefix,
                                  extra={"section": section, "declared": ver, "locked": bool(locked)}))
    return out


def _go_mod(ws: RepoWorkspace, path: Path) -> list[Dependency]:
    out: list[Dependency] = []
    rel = ws.rel(path)
    for i, line in enumerate(ws.read_text(path).splitlines(), 1):
        m = _GO_REQ.match(line)
        if m and "// indirect" not in line:
            out.append(Dependency(m.group(1), m.group(2), "Go", rel, i, "", True))
    return out


_SEMVERISH = r"v?(\d+(?:\.\d+){1,3}(?:[-.][0-9A-Za-z]+)*)"
_POM_DEP = re.compile(r"<dependency>(.*?)</dependency>", re.S)
_GRADLE = re.compile(r"""(?:implementation|api|compile|runtimeOnly|testImplementation|compileOnly)\s*\(?\s*['"]"""
                     r"""([\w.\-]+):([\w.\-]+):""" + _SEMVERISH + r"""['"]""")
_GEM_LOCK = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(" + _SEMVERISH + r"\)\s*$")
_CARGO = re.compile(r"""^\s*([A-Za-z0-9_\-]+)\s*=\s*(?:\{[^}]*version\s*=\s*)?"[=^~]?""" + _SEMVERISH + '"')
_NUGET = re.compile(r"""<PackageReference\s+Include="([^"]+)"\s+Version=""" + '"' + _SEMVERISH + '"')


def _line_of(lines: list[str], *needles: str) -> int:
    return next((i for i, ln in enumerate(lines, 1) if all(n in ln for n in needles)), 0)


def _pom(ws: RepoWorkspace, path: Path) -> list[Dependency]:
    text = ws.read_text(path)
    lines = text.splitlines()
    out: list[Dependency] = []
    for block in _POM_DEP.findall(text):
        g = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", block)
        a = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", block)
        v = re.search(r"<version>\s*" + _SEMVERISH + r"\s*</version>", block)
        if g and a and v:
            ln = next((i for i, row in enumerate(lines, 1) if f"<version>{v.group(1)}</version>" in row.replace(" ", "")
                       and i > _line_of(lines, f"<artifactId>{a.group(1)}</artifactId>")), 0)
            out.append(Dependency(f"{g.group(1)}:{a.group(1)}", v.group(1), "Maven", ws.rel(path), ln, "", True))
    return out


def _regex_manifest(ws: RepoWorkspace, path: Path, pattern: re.Pattern[str], ecosystem: str,
                    name_of: Any = None) -> list[Dependency]:
    out: list[Dependency] = []
    in_deps = path.name != "Cargo.toml"
    for i, line in enumerate(ws.read_text(path).splitlines(), 1):
        if path.name == "Cargo.toml" and line.strip().startswith("["):
            in_deps = "dependencies" in line
            continue
        m = pattern.match(line) if pattern is not _GRADLE and pattern is not _NUGET else pattern.search(line)
        if m and in_deps:
            name = name_of(m) if name_of else m.group(1)
            out.append(Dependency(name, m.groups()[-1], ecosystem, ws.rel(path), i, "", True))
    return out


def _composer(ws: RepoWorkspace, path: Path) -> list[Dependency]:
    try:
        data = json.loads(ws.read_text(path))
    except json.JSONDecodeError:
        return []
    lines = ws.read_text(path).splitlines()
    out: list[Dependency] = []
    for pkg in (data.get("packages") or []) + (data.get("packages-dev") or []):
        name, ver = pkg.get("name"), str(pkg.get("version", "")).lstrip("v")
        if name and re.match(r"^\d+\.\d+", ver):
            out.append(Dependency(name, ver, "Packagist", ws.rel(path), _line_of(lines, f'"{name}"'), "", True))
    return out


def discover_dependencies(ws: RepoWorkspace) -> list[Dependency]:
    deps: list[Dependency] = []
    for p in ws.iter_files(exts=set(), names={"package.json", "pyproject.toml", "go.mod", "pom.xml", "build.gradle",
                                              "build.gradle.kts", "Gemfile.lock", "composer.lock", "Cargo.toml"}):
        if p.name == "package.json":
            deps += _package_json(ws, p)
        elif p.name == "pyproject.toml":
            deps += _pyproject(ws, p)
        elif p.name == "go.mod":
            deps += _go_mod(ws, p)
        elif p.name == "pom.xml":
            deps += _pom(ws, p)
        elif p.name.startswith("build.gradle"):
            deps += _regex_manifest(ws, p, _GRADLE, "Maven", lambda m: f"{m.group(1)}:{m.group(2)}")
        elif p.name == "Gemfile.lock":
            deps += _regex_manifest(ws, p, _GEM_LOCK, "RubyGems")
        elif p.name == "composer.lock":
            deps += _composer(ws, p)
        elif p.name == "Cargo.toml":
            deps += _regex_manifest(ws, p, _CARGO, "crates.io")
    for p in ws.iter_files(exts={".csproj", ".fsproj", ".vbproj"}):
        deps += _regex_manifest(ws, p, _NUGET, "NuGet")
    for p in ws.iter_files(exts={".txt", ".in"}):
        if re.match(r"^requirements[\w.\-]*\.(txt|in)$", p.name) or p.parent.name == "requirements":
            deps += _requirements(ws, p)
    seen: set[tuple[str, str, str]] = set()
    unique: list[Dependency] = []
    for d in deps:
        key = (d.ecosystem, d.name.lower(), d.file)
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


def unified_diff(rel: str, before: str, after: str) -> str:
    """Unified diff produced by `git diff --no-index`, so CRLF files and missing final newlines apply cleanly."""
    if before == after:
        return ""
    with tempfile.TemporaryDirectory(prefix="skyforge-diff-") as tmp:
        (Path(tmp) / "a").write_bytes(before.encode("utf-8"))
        (Path(tmp) / "b").write_bytes(after.encode("utf-8"))
        res = subprocess.run(["git", "diff", "--no-index", "--no-color", "--no-ext-diff", "-U3", "a", "b"],
                             cwd=tmp, capture_output=True, timeout=30, check=False,
                             env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_NOSYSTEM": "1",
                                  "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": tmp})
    lines = res.stdout.decode("utf-8", errors="replace").splitlines(keepends=True)
    start = next((i for i, ln in enumerate(lines) if ln.startswith("--- ")), None)
    if start is None or start + 1 >= len(lines):
        return ""
    lines = lines[start:]
    lines[0], lines[1] = f"--- a/{rel}\n", f"+++ b/{rel}\n"
    return "".join(lines)


def upgrade_patch(ws: RepoWorkspace, dep: Dependency, new_version: str) -> str | None:
    """Rewrite only the dependency's own line. Returns a unified diff or None if the line cannot be located."""
    text = ws.read_text(dep.file)
    lines = text.splitlines(keepends=True)
    idx = dep.line - 1
    if not (0 <= idx < len(lines)):
        return None
    line = lines[idx]
    if dep.ecosystem == "npm":
        declared = dep.extra.get("declared", dep.version)
        prefix = dep.spec if dep.spec in ("^", "~") else ""
        new_line = line.replace(f'"{declared}"', f'"{prefix}{new_version}"', 1)
    elif dep.ecosystem == "Go":
        new_line = line.replace(f"v{dep.version}", f"v{new_version}", 1)
    elif dep.ecosystem in GENERIC_ECOSYSTEMS:
        new_line = line.replace(dep.version, new_version, 1)
    else:
        new_line = re.sub(rf"({re.escape(dep.spec)}\s*){re.escape(dep.version)}", rf"\g<1>{new_version}", line,
                          count=1)
    if new_line == line:
        return None
    lines[idx] = new_line
    return unified_diff(dep.file, text, "".join(lines))
