"""Wipe all scan data (projects, scans, findings, audit log, cloned workspaces, artifacts, uploaded AWS dumps).

Configuration (settings table, .env, bundled fixtures) is kept. CLI (server stopped):
    cd backend && ../.venv/bin/python -m app.services.reset --yes
"""

from __future__ import annotations

import shutil
import sys
from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.session import Base
from app.models import Setting

KEEP_TABLES = {Setting.__tablename__}


def wipe_all(db: Session, settings: Settings) -> dict[str, Any]:
    rows = 0
    for table in reversed(Base.metadata.sorted_tables):
        if table.name not in KEEP_TABLES:
            rows += db.execute(delete(table)).rowcount or 0
    db.commit()
    removed = []
    for d in (settings.workspaces_dir, settings.artifacts_dir, settings.data_dir / "aws_dumps"):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
            removed.append(d.name)
    settings.workspaces_dir.mkdir(parents=True, exist_ok=True)
    settings.artifacts_dir.mkdir(parents=True, exist_ok=True)
    return {"rows_deleted": rows, "directories_cleared": removed}


def _main() -> int:
    if "--yes" not in sys.argv:
        print("This deletes ALL projects, scans, findings, audit events, workspaces and artifacts.\n"
              "Re-run with --yes to confirm (stop the server first).")
        return 1
    from app.core.config import get_settings
    from app.db.migrate import upgrade_database
    from app.db.session import session_scope

    upgrade_database()
    with session_scope() as db:
        result = wipe_all(db, get_settings())
    print(f"SkyForge data cleared: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
