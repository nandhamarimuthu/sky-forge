"""Language registry: makes every agent polyglot.

Python keeps its exact AST-based inventory (see :mod:`code_metrics`). Every other language is understood through a
declarative :class:`LanguageSpec` that knows:

* which extensions belong to it and which paths are its tests,
* its idiomatic test framework, runner command and file naming convention,
* how to find top-level callable symbols (regex inventory — never executes repository code),
* how to find HTTP routes for its popular web frameworks.

Nothing here runs or imports repository code: it is pure text analysis, so an unknown/unsupported toolchain can
never break or slow down a scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.adapters.repository.git_repo import RepoWorkspace

# --------------------------------------------------------------------------------------- specs


@dataclass(frozen=True)
class LanguageSpec:
    id: str
    name: str
    exts: tuple[str, ...]
    test_framework: str
    runner: str
    """Shell command a developer runs locally/in CI to execute this language's tests."""
    test_path_template: str
    """`{stem}`/`{dir}` placeholders describing where a new test file belongs."""
    comment: str = "//"
    assert_style: str = ""
    package_manifests: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ()


LANGUAGES: dict[str, LanguageSpec] = {
    "python": LanguageSpec(
        "python", "Python", (".py",), "pytest", "pytest -q --cov",
        "tests/test_{stem}.py", "#", "assert value == expected",
        ("requirements.txt", "pyproject.toml", "setup.py"), ("fastapi", "flask", "django")),
    "javascript": LanguageSpec(
        "javascript", "JavaScript", (".js", ".jsx", ".mjs", ".cjs"), "jest", "npx jest --coverage",
        "{dir}/__tests__/{stem}.test.js", "//", "expect(value).toBe(expected)",
        ("package.json",), ("express", "koa", "hapi")),
    "typescript": LanguageSpec(
        "typescript", "TypeScript", (".ts", ".tsx"), "vitest", "npx vitest run --coverage",
        "{dir}/__tests__/{stem}.test.ts", "//", "expect(value).toBe(expected)",
        ("package.json", "tsconfig.json"), ("express", "nestjs")),
    "go": LanguageSpec(
        "go", "Go", (".go",), "go test", "go test ./... -cover",
        "{dir}/{stem}_test.go", "//", "if got != want { t.Fatalf(...) }",
        ("go.mod",), ("net/http", "gin", "echo", "chi", "fiber")),
    "java": LanguageSpec(
        "java", "Java", (".java",), "junit5", "mvn -q test  (or: gradle test)",
        "src/test/java/{stem}Test.java", "//", "assertEquals(expected, actual)",
        ("pom.xml", "build.gradle", "build.gradle.kts"), ("spring", "jax-rs")),
    "kotlin": LanguageSpec(
        "kotlin", "Kotlin", (".kt", ".kts"), "junit5", "gradle test",
        "src/test/kotlin/{stem}Test.kt", "//", "assertEquals(expected, actual)",
        ("build.gradle.kts", "build.gradle"), ("spring", "ktor")),
    "csharp": LanguageSpec(
        "csharp", "C#", (".cs",), "xunit", "dotnet test /p:CollectCoverage=true",
        "tests/{stem}Tests.cs", "//", "Assert.Equal(expected, actual)",
        ("*.csproj",), ("aspnetcore",)),
    "ruby": LanguageSpec(
        "ruby", "Ruby", (".rb",), "rspec", "bundle exec rspec --format documentation",
        "spec/{stem}_spec.rb", "#", "expect(value).to eq(expected)",
        ("Gemfile",), ("rails", "sinatra")),
    "php": LanguageSpec(
        "php", "PHP", (".php",), "phpunit", "vendor/bin/phpunit --coverage-text",
        "tests/{stem}Test.php", "//", "$this->assertSame($expected, $actual)",
        ("composer.json",), ("laravel", "symfony", "slim")),
    "rust": LanguageSpec(
        "rust", "Rust", (".rs",), "cargo test", "cargo test",
        "tests/{stem}_test.rs", "//", "assert_eq!(got, want)",
        ("Cargo.toml",), ("actix", "axum", "rocket")),
    "scala": LanguageSpec(
        "scala", "Scala", (".scala",), "scalatest", "sbt test",
        "src/test/scala/{stem}Spec.scala", "//", "result shouldBe expected",
        ("build.sbt",), ("play", "http4s")),
    "swift": LanguageSpec(
        "swift", "Swift", (".swift",), "xctest", "swift test",
        "Tests/{stem}Tests.swift", "//", "XCTAssertEqual(expected, actual)",
        ("Package.swift",), ("vapor",)),
    "terraform": LanguageSpec(
        "terraform", "Terraform", (".tf",), "terraform validate", "terraform validate && tflint",
        "tests/{stem}.tftest.hcl", "#", "", ("versions.tf",), ()),
    "shell": LanguageSpec(
        "shell", "Shell", (".sh", ".bash"), "bats", "bats tests/",
        "tests/{stem}.bats", "#", "[ \"$output\" = \"expected\" ]", (), ()),
}

EXT_TO_LANGUAGE: dict[str, str] = {ext: spec.id for spec in LANGUAGES.values() for ext in spec.exts}
ALL_CODE_EXTS: set[str] = set(EXT_TO_LANGUAGE)
# Languages whose unit/functional suites SkyForge can scaffold (terraform/shell are analysed but not scaffolded).
TESTABLE_LANGUAGES = tuple(k for k in LANGUAGES if k not in ("terraform", "shell"))


def language_for(rel: str) -> str | None:
    return EXT_TO_LANGUAGE.get(Path(rel).suffix.lower())


def spec_for(rel_or_lang: str) -> LanguageSpec | None:
    if rel_or_lang in LANGUAGES:
        return LANGUAGES[rel_or_lang]
    lang = language_for(rel_or_lang)
    return LANGUAGES.get(lang) if lang else None


# --------------------------------------------------------------------------------------- test paths

TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|e2e|testing|it|integration-tests?)(/|$)"
    r"|(^|/)test_[^/]+\.(py|rb)$"
    r"|_test\.(py|go|rb|dart|exs?)$"
    r"|_spec\.(rb|js|ts)$"
    r"|\.(test|spec)\.[jt]sx?$"
    r"|(^|/)[A-Z][\w$]*(Test|Tests|TestCase|Spec|IT)\.(java|kt|kts|cs|scala|php|swift)$"
    r"|(^|/)conftest\.py$"
    r"|\.bats$"
    r"|(^|/)src/test(/|$)",
)


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH.search(rel))


def test_path_for(rel: str) -> str | None:
    """Idiomatic location of the test file covering `rel`, or None for unsupported languages."""
    spec = spec_for(rel)
    if spec is None or spec.id in ("terraform", "shell"):
        return None
    p = Path(rel)
    directory = p.parent.as_posix()
    directory = "" if directory == "." else directory
    stem = p.stem
    out = spec.test_path_template.format(stem=stem, dir=directory or ".")
    return out.replace("./", "").replace("//", "/")


# --------------------------------------------------------------------------------------- symbols

BRANCH_KEYWORDS = re.compile(r"\b(if|else\s+if|elif|for|while|case|catch|rescue|when|match|&&|\|\||\?\?|\?)\b|[?]:")


@dataclass
class Symbol:
    """A callable discovered by text analysis in a non-Python language."""

    name: str
    file: str
    line: int
    language: str
    params: list[str] = field(default_factory=list)
    container: str | None = None
    exported: bool = True
    is_async: bool = False
    complexity: int = 1
    end_line: int = 0

    @property
    def qualname(self) -> str:
        return f"{self.container}.{self.name}" if self.container else self.name


# Each pattern must expose a named group `name`; `params` and `container` are optional.
SYMBOL_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "go": (
        re.compile(r"^func\s+(?:\((?P<container>[^)]*)\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)", re.M),
    ),
    "javascript": (
        re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?P<async>async\s+)?function\s*\*?\s*"
                   r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)", re.M),
        re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
                   r"(?P<async>async\s+)?(?:function\s*\*?\s*)?\((?P<params>[^)]*)\)\s*(?:=>|\{)", re.M),
        re.compile(r"^\s*(?:export\s+)?class\s+(?P<name>[A-Za-z_$][\w$]*)", re.M),
    ),
    "go_struct": (),
    "java": (
        re.compile(r"^\s*(?:public|protected|private)\s+(?:static\s+|final\s+|synchronized\s+|abstract\s+)*"
                   r"(?!class\b|interface\b|enum\b|record\b)[\w<>\[\],.?\s]+?\s+"
                   r"(?P<name>[a-z]\w*)\s*\((?P<params>[^)]*)\)\s*(?:throws [\w,. ]+)?\{", re.M),
        re.compile(r"^\s*(?:public\s+)?(?:final\s+|abstract\s+)?(?:class|interface|record|enum)\s+"
                   r"(?P<name>[A-Z]\w*)", re.M),
    ),
    "kotlin": (
        re.compile(r"^\s*(?:(?P<vis>public|internal|private|protected)\s+)?(?P<async>suspend\s+)?fun\s+"
                   r"(?:<[^>]+>\s*)?(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)", re.M),
    ),
    "csharp": (
        re.compile(r"^\s*(?:public|internal|protected|private)\s+(?:static\s+|virtual\s+|override\s+|sealed\s+|"
                   r"async\s+)*(?!class\b|interface\b|record\b|struct\b|enum\b)[\w<>\[\],.?\s]+?\s+"
                   r"(?P<name>[A-Z]\w*)\s*\((?P<params>[^)]*)\)", re.M),
    ),
    "ruby": (
        re.compile(r"^\s*def\s+(?:(?P<container>self)\.)?(?P<name>[a-zA-Z_]\w*[?!=]?)\s*(?:\((?P<params>[^)]*)\))?",
                   re.M),
    ),
    "php": (
        re.compile(r"^\s*(?:(?:public|protected|private)\s+)?(?:static\s+)?function\s+"
                   r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)", re.M),
    ),
    "rust": (
        re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?P<async>async\s+)?fn\s+(?P<name>[a-z_]\w*)"
                   r"\s*(?:<[^>]*>)?\s*\((?P<params>[^)]*)\)", re.M),
    ),
    "scala": (
        re.compile(r"^\s*(?:override\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\((?P<params>[^)]*)\)", re.M),
    ),
    "swift": (
        re.compile(r"^\s*(?:public\s+|internal\s+|private\s+|open\s+)?(?:static\s+)?func\s+"
                   r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)", re.M),
    ),
}

_PARAM_SPLIT = re.compile(r"\s*,\s*")


def _params(raw: str | None) -> list[str]:
    if not raw or not raw.strip():
        return []
    out = []
    for part in _PARAM_SPLIT.split(raw.strip()):
        tok = part.strip().split("=")[0].strip()
        if not tok or tok in ("self", "cls"):
            continue
        # `name type` (Go), `Type name` (Java/C#), `name: Type` (Kotlin/TS/Rust) — keep the identifier.
        if ":" in tok:
            tok = tok.split(":")[0]
        else:
            pieces = [t for t in tok.replace("*", " ").replace("&", " ").split() if t]
            tok = pieces[-1] if len(pieces) > 1 else (pieces[0] if pieces else tok)
        tok = tok.strip("()[]{}$@ ")
        if tok and re.match(r"^[A-Za-z_$]\w*$", tok):
            out.append(tok)
    return out[:10]


def _estimate_complexity(body: str) -> int:
    return min(60, 1 + len(BRANCH_KEYWORDS.findall(body)))


def inventory_symbols(ws: RepoWorkspace, path: Path, language: str | None = None) -> list[Symbol]:
    """Top-level callables in a non-Python source file. Returns [] for unsupported languages."""
    rel = ws.rel(path)
    lang = language or language_for(rel)
    patterns = SYMBOL_PATTERNS.get(lang or "")
    if not patterns:
        return []
    text = ws.read_text(path)
    lines = text.splitlines()
    seen: set[tuple[str, int]] = set()
    out: list[Symbol] = []
    for pattern in patterns:
        for m in pattern.finditer(text):
            name = m.group("name")
            line = text.count("\n", 0, m.start()) + 1
            if (name, line) in seen or name in ("if", "for", "while", "switch", "catch", "return", "function"):
                continue
            seen.add((name, line))
            groups = m.groupdict()
            end = min(len(lines), line + 80)
            body = "\n".join(lines[line - 1:end])
            out.append(Symbol(
                name=name, file=rel, line=line, language=lang or "unknown", params=_params(groups.get("params")),
                container=(groups.get("container") or "").strip().split()[-1] if groups.get("container") else None,
                exported=not name.startswith(("_", "#")) and (name[0].isupper() if lang == "go" else True),
                is_async=bool(groups.get("async")), complexity=_estimate_complexity(body), end_line=end))
    out.sort(key=lambda s: s.line)
    return out


# --------------------------------------------------------------------------------------- routes

HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")

# (language-or-"any", framework, compiled pattern, how to read method/path from the match)
_ROUTE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # --- Go: gin / echo / chi / fiber / gorilla / net-http
    ("go", "go-http", re.compile(r"\b\w*(?:Router|Mux|router|mux|app|api|srv|e|r|g|v\d)\w*\.(?P<verb>(?i:get|post|"
                                 r"put|patch|delete|head|options|handlefunc|handle))\(\s*\"(?P<path>/[^\"]*)\"")),
    ("go", "go-http", re.compile(r"http\.HandleFunc\(\s*\"(?P<path>/[^\"]*)\"")),
    # --- Java / Kotlin: Spring MVC & WebFlux
    ("java", "spring", re.compile(r"@(?P<verb>Get|Post|Put|Patch|Delete)Mapping\(\s*(?:value\s*=\s*)?[\"{]?"
                                  r"\"?(?P<path>[^\"})]*)")),
    ("java", "spring", re.compile(r"@RequestMapping\(\s*(?:value\s*=\s*)?\"(?P<path>[^\"]*)\"[^)]*"
                                  r"RequestMethod\.(?P<verb>GET|POST|PUT|PATCH|DELETE)")),
    ("kotlin", "spring", re.compile(r"@(?P<verb>Get|Post|Put|Patch|Delete)Mapping\(\s*(?:value\s*=\s*)?[\"{]?"
                                    r"\"?(?P<path>[^\"})]*)")),
    # --- C#: ASP.NET Core attribute routing and minimal APIs
    ("csharp", "aspnetcore", re.compile(r"\[Http(?P<verb>Get|Post|Put|Patch|Delete)(?:\(\"(?P<path>[^\"]*)\"\))?\]")),
    ("csharp", "aspnetcore", re.compile(r"\bapp\.Map(?P<verb>Get|Post|Put|Patch|Delete)\(\s*\"(?P<path>[^\"]*)\"")),
    # --- Ruby on Rails / Sinatra
    ("ruby", "rails", re.compile(r"^\s*(?P<verb>get|post|put|patch|delete)\s+['\"](?P<path>/[^'\"]*)['\"]", re.M)),
    # --- PHP: Laravel / Slim / Symfony annotations
    ("php", "laravel", re.compile(r"Route::(?P<verb>get|post|put|patch|delete)\(\s*['\"](?P<path>/[^'\"]*)['\"]")),
    ("php", "symfony", re.compile(r"#\[Route\(\s*['\"](?P<path>/[^'\"]*)['\"][^]]*methods:\s*\[['\"]"
                                  r"(?P<verb>GET|POST|PUT|PATCH|DELETE)")),
    # --- JS/TS: Express / Koa / Fastify / NestJS decorators
    ("javascript", "express", re.compile(r"\b(?:app|router|server|api|fastify)\.(?P<verb>get|post|put|patch|delete|"
                                         r"all)\(\s*['\"`](?P<path>[^'\"`]+)['\"`]")),
    ("typescript", "express", re.compile(r"\b(?:app|router|server|api|fastify)\.(?P<verb>get|post|put|patch|delete|"
                                         r"all)\(\s*['\"`](?P<path>[^'\"`]+)['\"`]")),
    ("typescript", "nestjs", re.compile(r"@(?P<verb>Get|Post|Put|Patch|Delete)\(\s*['\"`]?(?P<path>[^'\"`)]*)")),
    # --- Rust: actix / axum / rocket
    ("rust", "actix", re.compile(r"#\[(?P<verb>get|post|put|patch|delete)\(\s*\"(?P<path>/[^\"]*)\"")),
    ("rust", "axum", re.compile(r"\.route\(\s*\"(?P<path>/[^\"]*)\"\s*,\s*(?P<verb>get|post|put|patch|delete)\(")),
    # --- Python: Django URLConf (FastAPI/Flask are handled by the AST scanner)
    ("python", "django", re.compile(r"\b(?:path|re_path|url)\(\s*r?['\"](?P<path>[^'\"]*)['\"]")),
]

_AUTH_HINT = re.compile(r"(?i)(auth|token|jwt|bearer|login_required|@PreAuthorize|Authorize|requires_role|"
                        r"ensureAuth|passport|current_user|principal|UseGuards)")


def discover_routes_textual(ws: RepoWorkspace, path: Path, language: str | None = None) -> list[dict]:
    """Framework routes for non-Python languages (and Django), as plain dicts.

    Keys: framework, method, path, file, line, handler, requires_auth.
    """
    rel = ws.rel(path)
    lang = language or language_for(rel)
    if not lang:
        return []
    text = ws.read_text(path)
    lines = text.splitlines()
    base = ""
    for prefix_re in (r"@RequestMapping\(\s*(?:value\s*=\s*)?\"(/[^\"]*)\"\s*\)",
                      r"@Controller\(\s*['\"`](/?[^'\"`]*)['\"`]",
                      r"\[Route\(\"([^\"]*)\"\)\]"):
        m = re.search(prefix_re, text)
        if m and "{" not in m.group(1):
            base = "/" + m.group(1).strip("/")
            break
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for plang, framework, pattern in _ROUTE_PATTERNS:
        if plang != lang:
            continue
        for m in pattern.finditer(text):
            groups = m.groupdict()
            raw_path = (groups.get("path") or "").strip()
            verb = (groups.get("verb") or "GET").upper()
            if verb in ("HANDLEFUNC", "HANDLE", "ALL"):
                verb = "GET"
            if not raw_path:
                raw_path = "/"
            if not raw_path.startswith("/"):
                raw_path = "/" + raw_path
            full = (base.rstrip("/") + raw_path) if base and not raw_path.startswith(base) else raw_path
            full = re.sub(r"/{2,}", "/", full) or "/"
            line = text.count("\n", 0, m.start()) + 1
            if (verb, full) in seen:
                continue
            seen.add((verb, full))
            window = "\n".join(lines[max(0, line - 3):line + 4])
            out.append({"framework": framework, "method": verb, "path": full, "file": rel, "line": line,
                        "handler": _nearby_handler(lines, line, lang), "app_var": "",
                        "requires_auth": bool(_AUTH_HINT.search(window))})
    return out


def _nearby_handler(lines: list[str], line: int, lang: str) -> str:
    patterns = SYMBOL_PATTERNS.get(lang) or ()
    for offset in range(0, 6):
        for idx in (line - 1 + offset, line - 1 - offset):
            if not (0 <= idx < len(lines)):
                continue
            for pattern in patterns:
                m = pattern.search(lines[idx])
                if m:
                    return m.group("name")
    return ""


# --------------------------------------------------------------------------------------- repo profile


@dataclass
class LanguageProfile:
    """What the repository is written in, how much of it is tested, and with which tooling."""

    files: dict[str, int] = field(default_factory=dict)
    test_files: dict[str, int] = field(default_factory=dict)
    sloc: dict[str, int] = field(default_factory=dict)
    manifests: dict[str, list[str]] = field(default_factory=dict)

    @property
    def languages(self) -> list[str]:
        return [lang for lang, _ in sorted(self.files.items(), key=lambda kv: -kv[1])]

    @property
    def primary(self) -> str | None:
        non_iac = [lang for lang in self.languages if lang not in ("terraform", "shell")]
        return non_iac[0] if non_iac else (self.languages[0] if self.languages else None)

    def untested(self) -> list[str]:
        """Languages that carry real source files but have no test files at all."""
        return [lang for lang in self.languages
                if lang in TESTABLE_LANGUAGES and self.files.get(lang, 0) >= 2 and not self.test_files.get(lang)]

    def as_dict(self) -> dict:
        return {"files": self.files, "test_files": self.test_files, "sloc": self.sloc,
                "primary": self.primary, "manifests": self.manifests}


def profile_repository(ws: RepoWorkspace, max_files: int = 4000) -> LanguageProfile:
    profile = LanguageProfile()
    manifest_names = {name for spec in LANGUAGES.values() for name in spec.package_manifests if "*" not in name}
    for count, path in enumerate(ws.iter_files(ALL_CODE_EXTS | {".json", ".toml", ".xml", ".sbt", ".mod"})):
        if count >= max_files:
            break
        rel = ws.rel(path)
        if path.name in manifest_names:
            for lang, spec in LANGUAGES.items():
                if path.name in spec.package_manifests:
                    profile.manifests.setdefault(lang, []).append(rel)
        lang = language_for(rel)
        if not lang:
            continue
        bucket = profile.test_files if is_test_path(rel) else profile.files
        bucket[lang] = bucket.get(lang, 0) + 1
        if not is_test_path(rel):
            try:
                profile.sloc[lang] = profile.sloc.get(lang, 0) + sum(
                    1 for ln in ws.read_text(path).splitlines() if ln.strip())
            except OSError:  # pragma: no cover - unreadable file
                pass
    return profile
