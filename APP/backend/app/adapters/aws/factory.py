from __future__ import annotations

import re
from pathlib import Path

from app.adapters.aws.base import AwsAdapter
from app.adapters.aws.dump import DumpAwsAdapter
from app.core.config import Settings
from app.core.security import PathEscapeError, safe_join
from app.models import CloudAccountReference

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


def fixture_dumps_dir(settings: Settings) -> Path:
    return settings.fixtures_dir / "aws"


def uploaded_dump_dir(settings: Settings, project_id: str) -> Path:
    return settings.data_dir / "aws_dumps" / project_id


def resolve_dump(settings: Settings, dump_ref: str | None, project_id: str) -> Path | None:
    if not dump_ref:
        return None
    if dump_ref == "upload":
        p = uploaded_dump_dir(settings, project_id)
        return p if p.is_dir() else None
    if dump_ref.startswith("fixture:"):
        name = dump_ref.split(":", 1)[1]
        if not _NAME.match(name):
            return None
        try:
            p = safe_join(fixture_dumps_dir(settings), name)
        except PathEscapeError:
            return None
        return p if p.is_dir() else None
    return None


def available_fixture_dumps(settings: Settings) -> list[str]:
    root = fixture_dumps_dir(settings)
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "manifest.json").exists())


def build_aws_adapter(settings: Settings, account: CloudAccountReference | None,
                      iac_hints: list[dict] | None = None) -> AwsAdapter:
    tag = account.project_tag if account else ""
    regions = (account.regions if account and account.regions else [settings.aws_region])
    mode = account.mode if account else "dump"
    if mode == "live" and settings.aws_mode == "live":
        from app.adapters.aws.live import LiveAwsAdapter

        return LiveAwsAdapter(account.profile_ref if account else settings.aws_profile, regions,
                              settings.region_allowlist, settings.service_allowlist, tag)
    path = resolve_dump(settings, account.dump_ref, account.project_id) if account else None
    if path is not None:
        return DumpAwsAdapter(path, tag, iac_hints)
    missing = DumpAwsAdapter(settings.data_dir / "aws_dumps" / "__missing__", tag, iac_hints)
    ref = account.dump_ref if account else None
    missing.report.errors.append(f"AWS data dump '{ref}' not found — select or upload one on the AWS page" if ref
                                 else "No AWS cost data configured — select or upload a data dump on the AWS page")
    return missing
