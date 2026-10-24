"""Fail-closed JavaScript codemods. Tokenize data only; never load repository modules.

This is intentionally not a general JS parser. Unsupported lexical constructs disable
fixes, and aggregation extraction accepts one audited, closed function-body shape.
"""

from __future__ import annotations

import posixpath
import re
from collections import Counter
from dataclasses import dataclass


@dataclass(frozen=True)
class Token:
    value: str
    start: int
    end: int


_TOKEN = re.compile(
    r"""(?P<space>\s+)|(?P<comment>//[^\r\n]*|/\*[\s\S]*?\*/)"""
    r"""|(?P<string>'(?:[^'\\\r\n]|\\[^\r\n])*'|"(?:[^"\\\r\n]|\\[^\r\n])*")"""
    r"""|(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)|(?P<number>\d+(?:\.\d+)?)"""
    r"""|(?P<op>===|!==|=>|==|!=|<=|>=|\+=|-=|\*=|\|\||&&|\+\+|--|[{}()[\];,.:?+*%=<>!-])"""
)


def js_tokens(text: str) -> list[Token] | None:
    """Recognize a small JS lexical subset; reject templates, regexes, and escapes in names."""
    result: list[Token] = []
    offset = 0
    while offset < len(text):
        match = _TOKEN.match(text, offset)
        if not match:
            # Division is supported only surrounded by whitespace and numeric operands
            # in the audited aggregation body; regex literals remain unsupported.
            if text[offset:offset + 1] == "/" and text[max(0, offset - 1):offset].isspace():
                following = re.match(r"\s+\d", text[offset + 1:])
                if following:
                    result.append(Token("/", offset, offset + 1))
                    offset += 1
                    continue
            return None
        if match.lastgroup not in {"space", "comment"}:
            result.append(Token(match.group(), match.start(), match.end()))
        offset = match.end()
    return result


@dataclass(frozen=True)
class ImportEdit:
    line: int
    name: str
    original: str
    replacement: str


def unused_require_edits(text: str) -> list[ImportEdit]:
    """Drop only unused scalar lexical bindings, retaining require evaluation in place.

    Destructuring may invoke getters/iterators, ESM bindings affect link-time export
    validation, and var may create a global property: none are rewritten.
    """
    tokens = js_tokens(text)
    if tokens is None or any(t.value in {"eval", "with", "export", "import"} for t in tokens):
        return []
    counts = Counter(re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", text))
    out: list[ImportEdit] = []
    token_starts = {t.start for t in tokens}
    offset = 0
    depth = 0
    depths: dict[int, int] = {}
    for token in tokens:
        depths[token.start] = depth
        if token.value in {"{", "(", "["}:
            depth += 1
        elif token.value in {"}", ")", "]"}:
            depth -= 1
    pattern = re.compile(
        r"""(?P<indent>[ \t]*)(?:const|let) (?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"""
        r"""(?P<call>require\(\s*['"][^'"\\\r\n]+['"]\s*\));[ \t]*(?P<eol>\r?\n)?"""
    )
    for line_number, line in enumerate(text.splitlines(keepends=True), 1):
        match = pattern.fullmatch(line)
        if match:
            start = offset + len(match["indent"])
            # Top-level complete statements only, never text inside a comment/string.
            declared = re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", line).count(match["name"])
            if (match["name"] != "require" and start in token_starts and depths[start] == 0
                    and counts[match["name"]] == declared):
                out.append(ImportEdit(line_number, match["name"], line,
                                      match["indent"] + match["call"] + ";" + (match["eol"] or "")))
        offset += len(line)
    return out


def fix_unused_requires(text: str) -> str:
    edits = {edit.line: edit.replacement for edit in unused_require_edits(text)}
    return "".join(edits.get(i, line) for i, line in enumerate(text.splitlines(keepends=True), 1))


# The body has no module-local dependencies, this/arguments, async work, or
# identity-bearing results shared between invocations. Keep its evaluation order,
# Number coercion, rounding, prototype behaviour, and fresh per-call objects intact.
_AGGREGATION = """{
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
}"""
_HELPER = "summarizeRecords"


@dataclass(frozen=True)
class Function:
    name: str
    params: tuple[str, ...]
    body_start: int
    body_end: int
    body: tuple[str, ...]


def _plain_commonjs(text: str) -> tuple[list[Function], int, int] | None:
    """Accept only top-level function declarations and a shorthand exports object.

    No imports or top-level initialization means adding this module as a dependency
    cannot introduce initialization effects or a dependency cycle.
    """
    tokens = js_tokens(text)
    if not tokens:
        return None
    values = [t.value for t in tokens]
    if any(v in {"eval", "with", "global", "globalThis", "require", "__dirname", "__filename"} for v in values):
        return None
    functions: list[Function] = []
    i = 0
    while i < len(tokens) and values[i] == "function":
        if i + 3 >= len(tokens) or not re.fullmatch(r"[A-Za-z_$][\w$]*", values[i + 1]) or values[i + 2] != "(":
            return None
        name = values[i + 1]
        if name in {"Number", "Math", "module", "require", _HELPER}:
            return None
        i += 3
        param_start = i
        while i < len(tokens) and values[i] != ")":
            i += 1
        params = tuple(values[param_start:i])
        i += 1
        if i >= len(tokens) or values[i] != "{":
            return None
        start = i
        stack = ["{"]
        i += 1
        while i < len(tokens) and stack:
            value = values[i]
            if value in {"{", "(", "["}:
                stack.append(value)
            elif value in {"}", ")", "]"}:
                if not stack or stack.pop() != {"}": "{", ")": "(", "]": "["}[value]:
                    return None
            i += 1
        if stack:
            return None
        functions.append(Function(name, params, tokens[start].start, tokens[i - 1].end, tuple(values[start:i])))
    names = [f.name for f in functions]
    if not names or len(set(names)) != len(names):
        return None
    tail = values[i:]
    if tail[:4] != ["module", ".", "exports", "="] or tail[4:5] != ["{"] or tail[-2:] != ["}", ";"]:
        return None
    exported = tail[5:-2]
    if exported != [part for n, name in enumerate(names) for part in ([",", name] if n else [name])]:
        return None
    # module/exports must not also be manipulated from a function.
    if any(v in {"module", "exports"} for f in functions for v in f.body):
        return None
    return functions, tokens[i].start, tokens[-2].start


@dataclass
class JSRefactor:
    changes: dict[str, str]
    occurrences: list[tuple[str, int]]
    helper_file: str


def aggregation_refactor(sources: dict[str, str], max_consumers: int = 19) -> JSRefactor | None:
    """Consolidate exact aggregation clones into an existing inert utils module.

    Never create files (refactor policy forbids them). Named public wrappers keep
    their signatures; require stays lazy. At most 20 existing files are changed.
    """
    expected = tuple(t.value for t in js_tokens(_AGGREGATION) or [])
    parsed = {path: module for path, text in sources.items()
              if path.endswith((".js", ".cjs")) and (module := _plain_commonjs(text))}
    candidates = [(path, f) for path, (funcs, _, _) in sorted(parsed.items()) for f in funcs
                  if f.params == ("records",) and f.body == expected]
    if len(candidates) < 2:
        return None
    candidate_paths = {path for path, _ in candidates}
    helpers = [path for path in sorted(parsed) if "utils" in path.split("/")[:-1] and path not in candidate_paths]
    if not helpers:
        return None
    helper = helpers[0]
    # One function per consumer file avoids overlapping edits and ambiguous metrics.
    selected = []
    seen: set[str] = set()
    for path, function in candidates:
        if path not in seen:
            selected.append((path, function))
            seen.add(path)
        if len(selected) >= max_consumers:
            break
    if len(selected) < 2:
        return None
    text = sources[helper]
    eol = "\r\n" if "\r\n" in text else "\n"
    _, export_start, export_end = parsed[helper]
    helper_declaration = ("function " + _HELPER + "(records) " + _AGGREGATION + "\n\n").replace("\n", eol)
    changes = {helper: text[:export_start] + helper_declaration + text[export_start:export_end].rstrip()
               + ", " + _HELPER + " " + text[export_end:]}
    occurrences = []
    for path, function in selected:
        before = sources[path]
        relative = posixpath.relpath(helper, posixpath.dirname(path))
        if not relative.startswith("."):
            relative = "./" + relative
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", relative):
            return None
        eol = "\r\n" if "\r\n" in before else "\n"
        body = "{" + eol + f"  return require('{relative}').{_HELPER}(records);" + eol + "}"
        changes[path] = before[:function.body_start] + body + before[function.body_end:]
        occurrences.append((path, before.count("\n", 0, function.body_start) + 1))
    return JSRefactor(changes, occurrences, helper)


def verify_js_refactor(before: dict[str, str], after: dict[str, str]) -> bool:
    """Replay audited transformations against pristine before/after changed-file maps.

    Callers must obtain before from the trusted baseline, not the proposed patch;
    both maps must contain precisely all changed JS files. No syntax-count heuristic
    or repository code execution is used, and arbitrary edits fail closed.
    """
    if not before or before.keys() != after.keys() or any(before[p] == after[p] for p in before):
        return False
    plan = aggregation_refactor(before)
    if plan and plan.changes == after:
        return True
    return all(fix_unused_requires(text) == after[path] for path, text in before.items())
