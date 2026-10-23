"""CrewAI orchestration of the explanation step, backed by a local Ollama model.

Agents in the crew only *explain* already-validated findings. They have no tools, cannot modify files and their
output is parsed as untrusted JSON. If CrewAI or Ollama is unavailable, a direct Ollama call is attempted, and
finally deterministic templates are used — the scan never depends on the LLM.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

from app.services.llm import SYSTEM_GUARD, LLMService, wrap_untrusted

log = logging.getLogger(__name__)

ROLE_BY_AGENT = {
    "vulnerability": ("Application Security Engineer", "Explain dependency vulnerabilities and upgrade risk"),
    "unit_test": ("Test Engineer", "Explain coverage gaps and why the proposed tests matter"),
    "functional_test": ("QA Automation Engineer", "Explain functional journey gaps and failures"),
    "aws_optimizer": ("FinOps Engineer", "Explain AWS savings, evidence and operational risk"),
    "code_health": ("Staff Engineer", "Explain maintainability problems and refactoring value"),
    "guardrails": ("Cloud Security Reviewer", "Explain security policy violations and remediation"),
}


def template_explanation(f: dict[str, Any]) -> str:
    sev = f["severity"].upper()
    parts = [f"[{sev}] {f['title']}."]
    if f.get("description"):
        parts.append(f["description"].rstrip(".") + ".")
    if f.get("estimated_monthly_savings"):
        tag = "simulated" if f.get("data_source") == "simulated" else "estimated"
        parts.append(f"Potential saving ≈ ${f['estimated_monthly_savings']:.2f}/month ({tag}).")
    if f.get("recommendation"):
        parts.append(f"Recommended action: {f['recommendation']}")
    return " ".join(parts)


def _parse(text: str | None, ids: set[str]) -> dict[str, str]:
    if not text:
        return {}
    text = re.sub(r"```(?:json)?", "", text)
    m = re.search(r"\[.*\]|\{.*\}", text, re.S)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        try:
            data = json.loads(m.group(0).replace("{{", "{").replace("}}", "}"))
        except json.JSONDecodeError:
            return {}
    items = data if isinstance(data, list) else data.get("explanations", []) if isinstance(data, dict) else []
    out = {}
    for it in items:
        if isinstance(it, dict) and it.get("id") in ids and isinstance(it.get("explanation"), str):
            out[it["id"]] = it["explanation"].strip()[:1500]
    return out


def _prompt(agent_id: str, batch: list[dict[str, Any]]) -> str:
    payload = [{"id": f["id"], "severity": f["severity"], "title": f["title"], "evidence": f.get("evidence_summary"),
                "recommendation": f.get("recommendation")} for f in batch]
    return ("For each finding below write a 2–3 sentence explanation for an engineer: why it matters, the risk, and "
            "the safest next step. Do not invent facts beyond the evidence. Respond ONLY with JSON: "
            '[{"id": "...", "explanation": "..."}].\n\n' + wrap_untrusted(json.dumps(payload, default=str), 7000))


def explain_with_crew(llm: LLMService, findings: list[dict[str, Any]], batch_size: int = 6) -> tuple[dict[str, str], str]:
    """Returns (explanations by finding id, engine label)."""
    if not findings or not llm.usable:
        return {}, "template"
    by_agent: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_agent.setdefault(f["source_agent"], []).append(f)
    out: dict[str, str] = {}
    engine = "ollama"
    if llm.crewai_installed():
        try:
            out = _crew(llm, by_agent, batch_size)
            engine = "crewai+ollama"
        except Exception as exc:  # noqa: BLE001 - CrewAI raises many error types; fall back safely
            log.warning("CrewAI explanation failed (%s); falling back to direct Ollama", type(exc).__name__)
    for agent_id, items in by_agent.items():
        missing = [f for f in items if f["id"] not in out]
        for i in range(0, len(missing), batch_size):
            batch = missing[i:i + batch_size]
            out.update(_parse(llm.generate(_prompt(agent_id, batch), max_tokens=900, json_mode=True),
                              {f["id"] for f in batch}))
    return out, engine


def _crew(llm: LLMService, by_agent: dict[str, list[dict[str, Any]]], batch_size: int) -> dict[str, str]:
    # Finding data must never leave the machine: disable CrewAI/OpenTelemetry telemetry before import.
    os.environ["CREWAI_DISABLE_TELEMETRY"] = "true"
    os.environ["OTEL_SDK_DISABLED"] = "true"
    from crewai import LLM, Agent, Crew, Process, Task

    model = LLM(model=f"ollama/{llm.resolved_model()}", base_url=llm.settings.ollama_base_url, temperature=0.2)
    agents, tasks, batches = [], [], []
    for agent_id, items in by_agent.items():
        role, goal = ROLE_BY_AGENT.get(agent_id, ("Engineer", "Explain findings"))
        agent = Agent(role=role, goal=goal, backstory=SYSTEM_GUARD, llm=model, allow_delegation=False, tools=[],
                      verbose=False, max_iter=2)
        agents.append(agent)
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            batches.append(batch)
            tasks.append(Task(description=_prompt(agent_id, batch),
                              expected_output="A JSON array of id/explanation objects", agent=agent))
    crew = Crew(agents=agents, tasks=tasks, process=Process.sequential, verbose=False)
    crew.kickoff()
    out: dict[str, str] = {}
    for task, batch in zip(tasks, batches, strict=False):
        raw = getattr(task.output, "raw", None) if task.output else None
        out.update(_parse(raw, {f["id"] for f in batch}))
    return out
