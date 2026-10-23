"""Agent base class, execution context and explicit per-agent tool permissions."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.adapters.repository.git_repo import RepoWorkspace
from app.schemas.agents import AgentResult

TOOL_NAMES = {
    "repo.read": "Read files from the scan workspace (traversal-safe)",
    "osv.query": "Query the OSV.dev vulnerability database",
    "manifest.patch": "Generate dependency manifest patches (diff only)",
    "sandbox.execute": "Execute tests inside the isolated Docker sandbox",
    "static.ruff": "Run the Ruff linter (no code execution)",
    "static.radon": "Compute complexity/maintainability with Radon",
    "terraform.parse": "Parse Terraform resources",
    "aws.read": "Read-only AWS inventory, metrics and cost",
    "llm.generate": "Ask the local Ollama model for drafts and explanations",
}


class ToolPermissionError(PermissionError):
    pass


class CancelledError(Exception):
    pass


@dataclass
class AgentContext:
    scan_id: str
    project: dict[str, Any]
    workspace: RepoWorkspace
    options: dict[str, Any]
    tools: dict[str, Any]
    allowed_tools: frozenset[str]
    emit: Callable[..., None]
    cancel_event: threading.Event
    agent_id: str = ""
    used_tools: set[str] = field(default_factory=set)

    def tool(self, name: str) -> Any:
        if name not in self.allowed_tools:
            self.emit("agent.log", f"DENIED tool '{name}' — not in this agent's permission set", level="warning",
                      data={"denied_tool": name})
            raise ToolPermissionError(f"Agent '{self.agent_id}' is not permitted to use tool '{name}'")
        if name not in self.tools:
            raise ToolPermissionError(f"Tool '{name}' is not available in this deployment")
        self.used_tools.add(name)
        return self.tools[name]

    def has_tool(self, name: str) -> bool:
        return name in self.allowed_tools and name in self.tools

    def log(self, message: str, level: str = "info", **data: Any) -> None:
        self.emit("agent.log", message, level=level, data=data)

    def progress(self, value: float, message: str = "") -> None:
        self.emit("agent.progress", message, progress=max(0.0, min(1.0, value)))

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise CancelledError("Scan cancelled")


class BaseAgent(ABC):
    id: str
    name: str
    code: str
    description: str
    allowed_tools: frozenset[str]

    @abstractmethod
    def run(self, ctx: AgentContext) -> AgentResult: ...

    def meta(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "code": self.code, "description": self.description,
                "allowed_tools": sorted(self.allowed_tools)}
