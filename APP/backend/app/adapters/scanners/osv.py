"""OSV.dev vulnerability lookups (https://osv.dev) with CVSS v3 base-score computation."""

from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass, field
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    severity: str  # critical|high|medium|low
    cvss_score: float | None
    fixed_versions: list[str]
    references: list[str]
    published: str | None
    details: str = ""
    raw_severity: dict[str, Any] = field(default_factory=dict)


_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _W["C"][parts["C"]]) * (1 - _W["C"][parts["I"]]) * (1 - _W["C"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploit = 8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * pr * _W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        raw = 1.08 * (impact + exploit) if scope_changed else impact + exploit
        return _roundup(min(raw, 10))
    except (KeyError, ValueError, IndexError):
        return None


def score_to_severity(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _numeric(v: str) -> tuple[int, ...]:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v.lstrip("v"))[:4])


def version_key(ecosystem: str, v: str) -> tuple:
    try:
        return (Version(v.lstrip("v")),)
    except InvalidVersion:
        return (Version(".".join(str(n) for n in _numeric(v)) or "0"),)


def _cmp_lt(ecosystem: str, a: str, b: str) -> bool:
    return version_key(ecosystem, a) < version_key(ecosystem, b)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class OSVClient:
    def __init__(self, base_url: str, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._cache: dict[tuple[str, str, str], list[Advisory]] = {}
        self._lock = threading.Lock()

    def query(self, name: str, ecosystem: str, version: str) -> list[Advisory]:
        key = (ecosystem, name.lower(), version)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        vulns: list[dict[str, Any]] = []
        with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
            page_token: str | None = None
            for _ in range(5):
                body = dict(payload, **({"page_token": page_token} if page_token else {}))
                resp = client.post(f"{self.base_url}/v1/query", json=body)
                resp.raise_for_status()
                data = resp.json()
                vulns.extend(data.get("vulns", []) or [])
                page_token = data.get("next_page_token")
                if not page_token:
                    break
        advisories = self._dedupe([self._parse(v, name, ecosystem, version) for v in vulns])
        with self._lock:
            self._cache[key] = advisories
        return advisories

    @staticmethod
    def _dedupe(items: list[Advisory]) -> list[Advisory]:
        """OSV returns the same issue under several IDs (PYSEC/GHSA/CVE); keep one, preferring GHSA."""
        items.sort(key=lambda a: (not a.id.startswith("GHSA"), a.id))
        seen: set[str] = set()
        out: list[Advisory] = []
        for adv in items:
            ids = {adv.id, *adv.aliases}
            if ids & seen:
                continue
            seen |= ids
            out.append(adv)
        return out

    @staticmethod
    def _parse(v: dict[str, Any], name: str, ecosystem: str, version: str) -> Advisory:
        score: float | None = None
        for sev in v.get("severity", []) or []:
            if str(sev.get("type", "")).startswith("CVSS_V3") and str(sev.get("score", "")).startswith("CVSS:3"):
                score = cvss3_base_score(sev["score"])
                break
        label = score_to_severity(score)
        db_sev = str((v.get("database_specific") or {}).get("severity", "")).lower()
        if not label:
            label = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium",
                     "low": "low"}.get(db_sev, "medium")
        fixed: set[str] = set()
        for aff in v.get("affected", []) or []:
            pkg = aff.get("package") or {}
            if _norm(pkg.get("name", "")) != _norm(name):
                continue
            for rng in aff.get("ranges", []) or []:
                for ev in rng.get("events", []) or []:
                    if "fixed" in ev:
                        fixed.add(str(ev["fixed"]))
        later = sorted((f for f in fixed if _cmp_lt(ecosystem, version, f)), key=lambda f: version_key(ecosystem, f))
        refs = [r.get("url", "") for r in (v.get("references") or [])][:6]
        return Advisory(id=v.get("id", "UNKNOWN"), aliases=list(v.get("aliases", []) or []),
                        summary=(v.get("summary") or v.get("details", "")[:200] or v.get("id", "")).strip(),
                        severity=label, cvss_score=score, fixed_versions=later, references=refs,
                        published=v.get("published"), details=(v.get("details") or "")[:1500],
                        raw_severity={"database": db_sev, "cvss": score})


def minimal_safe_version(ecosystem: str, current: str, advisories: list[Advisory]) -> str | None:
    """Smallest version that is >= every advisory's first fixed version above `current`."""
    candidates: list[str] = []
    for adv in advisories:
        if not adv.fixed_versions:
            return None
        candidates.append(adv.fixed_versions[0])
    if not candidates:
        return None
    return max(candidates, key=lambda f: version_key(ecosystem, f))


def is_major_bump(ecosystem: str, current: str, target: str) -> bool:
    def major(v: str) -> int:
        head = v.lstrip("v").split(".")[0]
        return int(head) if head.isdigit() else -1

    cur, tgt = major(current), major(target)
    if cur == 0 and tgt == 0:
        return current.lstrip("v").split(".")[1:2] != target.lstrip("v").split(".")[1:2]
    return cur != tgt
