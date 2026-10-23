from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.errors import ApiError
from app.core.ratelimit import rate_limiter
from app.core.security import Principal
from app.db.session import get_db
from app.models import Project
from app.services.audit import audit
from app.services.container import Container, get_container


def container() -> Container:
    return get_container()


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_principal(request: Request, db: Session = Depends(get_db), c: Container = Depends(container)) -> Principal:
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else None
    principal = c.tokens.resolve(token)
    if principal is None:
        allowed, _ = rate_limiter.allow(f"authfail:{client_ip(request)}", 30)
        if allowed:
            audit(db, "anonymous", "auth.failed", "endpoint", request.url.path, "denied", {}, client_ip(request))
        raise ApiError(401, "unauthorized", "Missing or invalid bearer token")
    ok, retry = rate_limiter.allow(f"api:{principal.name}", c.settings.rate_limit_per_minute)
    if not ok:
        raise ApiError(429, "rate_limited", f"Too many requests; retry in {retry}s", {"retry_after": retry})
    request.state.principal = principal
    return principal


def require(permission: str) -> Callable[..., Principal]:
    def dep(request: Request, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> Principal:
        if not principal.can(permission):
            audit(db, principal.name, "access.denied", "permission", permission, "denied",
                  {"path": request.url.path, "role": principal.role}, client_ip(request))
            raise ApiError(403, "forbidden", f"Role '{principal.role}' lacks permission '{permission}'")
        return principal

    return dep


def load_project(db: Session, principal: Principal, project_id: str, request: Request | None = None) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise ApiError(404, "not_found", "Project not found")
    if not principal.can_access_project(project.id, project.name):
        audit(db, principal.name, "access.denied", "project", project_id, "denied", {},
              client_ip(request) if request else None)
        raise ApiError(404, "not_found", "Project not found")
    return project


def accessible_project_ids(db: Session, principal: Principal) -> list[str]:
    rows = db.query(Project.id, Project.name).all()
    return [pid for pid, name in rows if principal.can_access_project(pid, name)]
