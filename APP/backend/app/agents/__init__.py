from __future__ import annotations

from app.agents.aws_optimizer_agent import AwsOptimizerAgent
from app.agents.base import BaseAgent
from app.agents.code_health_agent import CodeHealthAgent
from app.agents.functional_test_agent import FunctionalTestAgent
from app.agents.security_guardrails import SecurityGuardrailsAgent
from app.agents.unit_test_agent import UnitTestAgent
from app.agents.vulnerability_agent import VulnerabilityAgent

AGENTS: dict[str, BaseAgent] = {a.id: a for a in (
    VulnerabilityAgent(), UnitTestAgent(), FunctionalTestAgent(), AwsOptimizerAgent(), CodeHealthAgent(),
    SecurityGuardrailsAgent(),
)}
