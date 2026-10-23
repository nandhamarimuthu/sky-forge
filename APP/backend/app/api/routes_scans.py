from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import accessible_project_ids, client_ip, container, get_principal, load_project, require
from app.core.errors import ApiError
from app.core.security import Principal, safe_join
from app.db.session import SessionLocal, get_db
from app.models import Project, Scan, ScanArtifact, ScanEvent
from app.orchestration.orchestrator import TERMINAL
from app.schemas.api import ArtifactOut, Page, ScanEventOut, ScanOut
from app.services.audit import audit
from app.services.container import Container
from app.services.views import scan_out

router = APIRouter(prefix="/scans", tags=["scans"])


def _load_scan(db: Session, principal: Principal, scan_id: str, request: Request) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ApiError(404, "not_found", "Scan not found")
    load_project(db, principal, scan.project_id, request)
    return scan


@router.get("", response_model=Page[ScanOut])
def list_scans(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
               status_: str | None = Query(None, alias="status", max_length=20), db: Session = Depends(get_db),
               principal: Principal = Depends(get_principal)) -> Page[ScanOut]:
    ids = accessible_project_ids(db, principal)
    stmt = select(Scan).where(Scan.project_id.in_(ids))
    if status_:
        stmt = stmt.where(Scan.status == status_)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).scalars()
    names: dict[str, str] = {k: v for k, v in db.execute(select(Project.id, Project.name)).all()}
    return Page(items=[scan_out(db, s, project_name=names.get(s.project_id)) for s in rows], total=total, page=page,
                page_size=page_size)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, request: Request, db: Session = Depends(get_db),
             principal: Principal = Depends(get_principal)) -> ScanOut:
    scan = _load_scan(db, principal, scan_id, request)
    project = db.get(Project, scan.project_id)
    return scan_out(db, scan, project_name=project.name if project else None)


@router.get("/{scan_id}/events", response_model=None)
async def scan_events(scan_id: str, request: Request, after: int = Query(0, ge=0),
                      stream: bool = Query(True), db: Session = Depends(get_db),
                      principal: Principal = Depends(get_principal)) -> StreamingResponse | list[ScanEventOut]:
    _load_scan(db, principal, scan_id, request)
    if not stream:
        rows = db.execute(select(ScanEvent).where(ScanEvent.scan_id == scan_id, ScanEvent.id > after)
                          .order_by(ScanEvent.id).limit(1000)).scalars()
        return [ScanEventOut.model_validate(r) for r in rows]

    async def gen() -> AsyncIterator[str]:
        last = after
        idle = 0
        yield "retry: 3000\n\n"
        while True:
            if await request.is_disconnected():
                return
            with SessionLocal() as s:
                rows = s.execute(select(ScanEvent).where(ScanEvent.scan_id == scan_id, ScanEvent.id > last)
                                 .order_by(ScanEvent.id).limit(200)).scalars().all()
                scan = s.get(Scan, scan_id)
                snapshot = {"status": scan.status, "progress": scan.progress} if scan else None
            for r in rows:
                last = r.id
                payload = ScanEventOut.model_validate(r).model_dump(mode="json")
                yield f"id: {r.id}\nevent: {r.type}\ndata: {json.dumps(payload)}\n\n"
            if snapshot:
                yield f"event: snapshot\ndata: {json.dumps(snapshot)}\n\n"
            if snapshot and snapshot["status"] in TERMINAL and not rows:
                yield "event: end\ndata: {}\n\n"
                return
            idle = 0 if rows else idle + 1
            if idle and idle % 30 == 0:
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.6)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/{scan_id}/cancel", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def cancel_scan(scan_id: str, request: Request, db: Session = Depends(get_db),
                principal: Principal = Depends(require("scan:cancel")), c: Container = Depends(container)) -> ScanOut:
    scan = _load_scan(db, principal, scan_id, request)
    if scan.status in TERMINAL:
        raise ApiError(409, "already_finished", f"Scan is already {scan.status}")
    if scan.status == "queued" and not c.worker.cancel(scan_id):
        scan.status = "cancelled"
    else:
        c.worker.cancel(scan_id)
    db.add(ScanEvent(scan_id=scan_id, type="scan.log", level="warning", message=f"Cancellation requested by "
                                                                                  f"{principal.name}"))
    audit(db, principal.name, "scan.cancel", "scan", scan_id, "allowed", {}, client_ip(request))
    return scan_out(db, scan)


@router.get("/{scan_id}/artifacts", response_model=list[ArtifactOut])
def list_artifacts(scan_id: str, request: Request, db: Session = Depends(get_db),
                   principal: Principal = Depends(get_principal)) -> list[ArtifactOut]:
    _load_scan(db, principal, scan_id, request)
    rows = db.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id).order_by(ScanArtifact.created_at))
    return [ArtifactOut.model_validate(a) for a in rows.scalars()]


@router.get("/{scan_id}/artifacts/{artifact_id}")
def get_artifact(scan_id: str, artifact_id: str, request: Request, db: Session = Depends(get_db),
                 principal: Principal = Depends(get_principal), c: Container = Depends(container)) -> FileResponse:
    _load_scan(db, principal, scan_id, request)
    art = db.get(ScanArtifact, artifact_id)
    if art is None or art.scan_id != scan_id:
        raise ApiError(404, "not_found", "Artifact not found")
    path = safe_join(c.settings.artifacts_dir, art.rel_path)
    if not path.is_file():
        raise ApiError(410, "gone", "Artifact file no longer available")
    audit(db, principal.name, "artifact.download", "artifact", artifact_id, "allowed", {"scan": scan_id},
          client_ip(request))
    # Always served as an attachment with a non-executable type to avoid content sniffing / XSS.
    media = "application/json" if art.media_type == "application/json" else "text/plain; charset=utf-8"
    return FileResponse(path, media_type=media, filename=art.name,
                        headers={"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'"})
