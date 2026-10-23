"""Process-wide service container (built once at startup, replaceable in tests)."""

from __future__ import annotations

from dataclasses import dataclass

from app.adapters.sandbox import DockerSandbox
from app.adapters.scanners.osv import OSVClient
from app.core.config import Settings, get_settings
from app.core.security import TokenRegistry
from app.orchestration.orchestrator import ScanOrchestrator
from app.services.llm import LLMService
from app.workers.runner import ScanWorker


@dataclass
class Container:
    settings: Settings
    tokens: TokenRegistry
    llm: LLMService
    sandbox: DockerSandbox
    osv: OSVClient
    orchestrator: ScanOrchestrator
    worker: ScanWorker


_container: Container | None = None


def build_container(settings: Settings | None = None) -> Container:
    s = settings or get_settings()
    llm = LLMService(s)
    sandbox = DockerSandbox(s.sandbox_python_image, s.sandbox_memory, s.sandbox_cpus, s.sandbox_timeout_s,
                            enabled=s.sandbox_enabled)
    osv = OSVClient(s.osv_api_url, s.osv_timeout_s)
    orch = ScanOrchestrator(s, llm, sandbox, osv)
    worker = ScanWorker(orch.run, max_workers=s.max_concurrent_scans)
    return Container(s, TokenRegistry(s), llm, sandbox, osv, orch, worker)


def get_container() -> Container:
    global _container
    if _container is None:
        _container = build_container()
    return _container


def set_container(c: Container | None) -> None:
    global _container
    _container = c
