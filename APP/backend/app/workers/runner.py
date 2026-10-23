"""Background worker with durable status tracking (state lives in the DB, not in request handlers)."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select

from app.db.session import session_scope
from app.models import AgentRun, Scan, ScanEvent, utcnow

log = logging.getLogger(__name__)


class ScanWorker:
    def __init__(self, run_fn: Callable[[str, threading.Event], None], max_workers: int = 2):
        self._run_fn = run_fn
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan-worker")
        self._side_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="remediation-worker")
        self._cancel: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def submit(self, scan_id: str) -> None:
        with self._lock:
            ev = self._cancel.setdefault(scan_id, threading.Event())
        self._pool.submit(self._wrapped, scan_id, ev)

    def submit_task(self, fn: Callable[[], None]) -> None:
        self._side_pool.submit(fn)

    def _wrapped(self, scan_id: str, ev: threading.Event) -> None:
        try:
            self._run_fn(scan_id, ev)
        finally:
            with self._lock:
                self._cancel.pop(scan_id, None)

    def cancel(self, scan_id: str) -> bool:
        with self._lock:
            ev = self._cancel.get(scan_id)
        if ev:
            ev.set()
            return True
        return False

    def cancel_all(self) -> int:
        with self._lock:
            events = list(self._cancel.values())
        for ev in events:
            ev.set()
        return len(events)

    def active(self) -> int:
        with self._lock:
            return len(self._cancel)

    def reconcile(self) -> None:
        """On startup: fail scans interrupted by a restart and resubmit queued ones."""
        with session_scope() as db:
            for scan in db.execute(select(Scan).where(Scan.status == "running")).scalars():
                scan.status, scan.error, scan.finished_at = "failed", "Interrupted by server restart", utcnow()
                for run in db.execute(select(AgentRun).where(AgentRun.scan_id == scan.id,
                                                             AgentRun.status.in_(["queued", "running"]))).scalars():
                    run.status, run.error = "failed", "Interrupted by server restart"
                db.add(ScanEvent(scan_id=scan.id, type="scan.status", level="error",
                                 message="Scan interrupted by server restart",
                                 data={"status": "failed", "terminal": True}))
            queued = [s.id for s in db.execute(select(Scan).where(Scan.status == "queued")).scalars()]
        for sid in queued:
            self.submit(sid)
        if queued:
            log.info("Resubmitted %d queued scan(s)", len(queued))

    def shutdown(self) -> None:
        for ev in list(self._cancel.values()):
            ev.set()
        self._pool.shutdown(wait=False, cancel_futures=True)
        self._side_pool.shutdown(wait=False, cancel_futures=True)
