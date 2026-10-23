from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.security import redact
from app.models import AuditEvent


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)[:2000]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in list(value.items())[:50]}
    if isinstance(value, list | tuple):
        return [_clean(v) for v in list(value)[:50]]
    return value


def audit(db: Session, actor: str, action: str, target_type: str = "", target_id: str = "",
          outcome: str = "allowed", details: dict[str, Any] | None = None, ip: str | None = None,
          commit: bool = True) -> AuditEvent:
    ev = AuditEvent(actor=actor, action=action, target_type=target_type, target_id=target_id, outcome=outcome,
                    details=_clean(details or {}), ip=ip)
    db.add(ev)
    if commit:
        db.commit()
    return ev
