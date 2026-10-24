"""Minimal HCL block extractor for Terraform files — enough for policy checks and IaC-linked recommendations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.adapters.repository.git_repo import RepoWorkspace

_BLOCK = re.compile(r'^\s*resource\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_\-]+)"\s*\{', re.M)
_ATTR = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$')


@dataclass
class TfResource:
    type: str
    name: str
    file: str
    start_line: int
    end_line: int
    body: str
    attrs: dict[str, tuple[str, int]] = field(default_factory=dict)  # key -> (raw value, absolute line)

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"

    def value(self, key: str) -> str | None:
        v = self.attrs.get(key)
        if not v:
            return None
        raw = v[0].split("#", 1)[0].strip()
        return raw[1:-1] if raw.startswith('"') and raw.endswith('"') else raw

    def attr_line(self, key: str, expected: str | None = None) -> int | None:
        """Absolute line of `key = …`, including attributes nested in sub-blocks (e.g. root_block_device).

        Returns None when the attribute is absent or appears more than once, so callers never patch ambiguously.
        """
        top = self.attrs.get(key)
        if top and (expected is None or expected in top[0]):
            return top[1]
        pat = re.compile(rf'(?<![A-Za-z0-9_]){re.escape(key)}\s*=\s*(.+?)\s*$')
        hits = [self.start_line + off for off, line in enumerate(self.body.splitlines())
                if (m := pat.search(line.split("#", 1)[0])) and (expected is None or expected in m.group(1))]
        return hits[0] if len(hits) == 1 else None


def parse_terraform(ws: RepoWorkspace) -> list[TfResource]:
    out: list[TfResource] = []
    for path in ws.iter_files({".tf"}):
        text = ws.read_text(path)
        rel = ws.rel(path)
        for m in _BLOCK.finditer(text):
            start = m.end()
            depth, i = 1, start
            while i < len(text) and depth:
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                i += 1
            body = text[start:i - 1]
            # m.start() may sit on a preceding blank line (`^\s*` crosses newlines) — anchor on the type name.
            start_line = text.count("\n", 0, m.start(1)) + 1
            res = TfResource(m.group(1), m.group(2), rel, start_line, text.count("\n", 0, i) + 1, body)
            nested = 0
            for offset, line in enumerate(body.splitlines()):
                stripped = line.strip()
                if nested == 0:
                    am = _ATTR.match(line)
                    if am and not am.group(2).endswith("{"):
                        res.attrs.setdefault(am.group(1), (am.group(2), start_line + offset))
                nested += stripped.count("{") - stripped.count("}")
                nested = max(nested, 0)
            out.append(res)
    return out
