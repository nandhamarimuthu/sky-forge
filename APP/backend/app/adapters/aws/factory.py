from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import date
from pathlib import Path
from threading import Lock

from app.adapters.aws.base import AwsAdapter
from app.adapters.aws.dump import DumpAwsAdapter
from app.adapters.aws.iac_dump import generate_dump
from app.adapters.scanners.terraform import TfResource
from app.core.config import Settings
from app.models import CloudAccountReference

_GENERATE_LOCK = Lock()


def generated_dump_dir(settings: Settings, project_id: str) -> Path:
    return settings.data_dir / "aws_dumps" / f"{project_id}__iac"


def build_aws_adapter(settings: Settings, account: CloudAccountReference | None,
                      iac_hints: list[dict] | None = None,
                      terraform: list[TfResource] | None = None) -> AwsAdapter:
    """Only the current repository's Terraform may supply optimiser inventory."""
    tag = account.project_tag if account else ""
    regions = (account.regions if account and account.regions else [settings.aws_region])
    tf = terraform or []
    fingerprint = hashlib.sha256(json.dumps(
        {"terraform": [asdict(r) for r in tf], "tag": tag, "region": regions[0]},
        sort_keys=True).encode()).hexdigest()
    dest = (generated_dump_dir(settings, account.project_id if account else "unassigned")
            / fingerprint / date.today().isoformat())
    # Different repository revisions must not overwrite a dump still being read by another scan.
    with _GENERATE_LOCK:
        generated = generate_dump(tf, dest, tag, regions[0])
    adapter = DumpAwsAdapter(generated, tag, iac_hints)
    adapter.report.meta["terraform_fingerprint"] = fingerprint
    if not adapter.inventory():
        adapter.report.errors.append(
            "No supported Terraform AWS resources found in the scanned repository. "
            "Scan a repository containing AWS resource declarations; external dumps are not used.")
    return adapter
