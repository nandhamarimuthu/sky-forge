"""AWS adapter contracts. All adapters are read-only by construction: no mutating methods exist."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class Resource:
    id: str
    service: str  # ec2 | ebs | snapshot | rds | natgateway | elb | lambda | s3
    region: str
    type: str
    state: str
    name: str
    tags: dict[str, str] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    monthly_cost: float | None = None  # list-price estimate
    iac_address: str | None = None


@dataclass
class MetricSeries:
    resource_id: str
    metric: str
    unit: str
    period: str  # e.g. "1d"
    points: list[tuple[str, float]]  # (ISO date, value)


@dataclass
class CostSeries:
    granularity: str
    currency: str
    start: str
    end: str
    by_service: dict[str, list[tuple[str, float]]]
    measured: bool  # True only when sourced from Cost Explorer


@dataclass
class AdapterReport:
    mode: str  # dump | live
    simulated: bool
    missing_evidence: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


class AwsAdapter(Protocol):
    report: AdapterReport

    def inventory(self) -> list[Resource]: ...

    def metrics(self, resource: Resource, days: int = 14) -> list[MetricSeries]: ...

    def cost(self, days: int = 90) -> CostSeries | None: ...
