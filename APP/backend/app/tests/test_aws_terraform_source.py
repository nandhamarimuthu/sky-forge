from __future__ import annotations

import pytest

from app.adapters.aws.factory import build_aws_adapter
from app.adapters.repository.git_repo import RepoWorkspace
from app.adapters.scanners.terraform import parse_terraform
from app.models import CloudAccountReference
from app.tests.conftest import ADMIN, VIEWER


def _account(ref: str | None, mode: str = "dump") -> CloudAccountReference:
    return CloudAccountReference(project_id="terraform-only", dump_ref=ref, mode=mode,
                                 project_tag="repo-only", regions=["eu-west-2"])


def _terraform(tmp_path, source: str):
    (tmp_path / "main.tf").write_text(source, encoding="utf-8")
    return parse_terraform(RepoWorkspace(tmp_path))


@pytest.mark.parametrize("ref,mode", [
    ("fixture:shared-platform", "dump"), ("fixture:demo-shop", "dump"),
    ("upload", "dump"), ("terraform", "dump"), ("iac", "dump"), (None, "live"),
])
def test_only_current_terraform_is_used(settings, tmp_path, ref, mode):
    cfg = settings.model_copy(update={"data_dir": tmp_path / "data", "aws_mode": mode})
    tf = _terraform(tmp_path, 'resource "aws_instance" "only_here" {\n  instance_type = "m5.2xlarge"\n}\n')
    adapter = build_aws_adapter(cfg, _account(ref, mode), terraform=tf)
    assert {r.iac_address for r in adapter.inventory()} == {"aws_instance.only_here"}
    assert adapter.report.meta["source"] == "terraform"
    assert adapter.report.simulated and not adapter.cost().measured

    changed = _terraform(tmp_path, 'resource "aws_s3_bucket" "replacement" {\n  bucket = "repo-replacement"\n}\n')
    newer = build_aws_adapter(cfg, _account(ref, mode), terraform=changed)
    assert {r.iac_address for r in newer.inventory()} == {"aws_s3_bucket.replacement"}
    assert newer.report.meta["terraform_fingerprint"] != adapter.report.meta["terraform_fingerprint"]
    assert {r.iac_address for r in adapter.inventory()} == {"aws_instance.only_here"}

    empty = build_aws_adapter(cfg, _account(ref, mode), terraform=[])
    assert empty.inventory() == [] and empty.cost() is None
    assert empty.report.errors and empty.report.meta["source"] == "terraform"


def test_regenerates_instead_of_reading_existing_generated_dump(settings, tmp_path):
    cfg = settings.model_copy(update={"data_dir": tmp_path / "data"})
    tf = _terraform(tmp_path, 'resource "aws_instance" "current" {\n  instance_type = "t3.micro"\n}\n')
    first = build_aws_adapter(cfg, _account("terraform"), terraform=tf)
    # Even a pre-existing generated file is not accepted as an input.
    (first.dir / "ec2_instances.json").write_text('{"Reservations": []}', encoding="utf-8")
    second = build_aws_adapter(cfg, _account("terraform"), terraform=tf)
    assert {r.iac_address for r in second.inventory()} == {"aws_instance.current"}


def test_unpriced_resources_and_projects_without_cloud_account(settings, tmp_path):
    cfg = settings.model_copy(update={"data_dir": tmp_path / "data"})
    tf = _terraform(tmp_path, 'resource "aws_instance" "unpriced" {\n  instance_type = "unknown.large"\n}\n')
    adapter = build_aws_adapter(cfg, None, terraform=tf)
    assert {r.iac_address for r in adapter.inventory()} == {"aws_instance.unpriced"}
    assert adapter.cost() is None


def test_zero_count_does_not_create_resources(settings, tmp_path):
    cfg = settings.model_copy(update={"data_dir": tmp_path / "data"})
    tf = _terraform(tmp_path, 'resource "aws_instance" "disabled" {\n  count = 0\n  instance_type = "t3.micro"\n}\n')
    assert build_aws_adapter(cfg, None, terraform=tf).inventory() == []


def test_new_projects_do_not_select_a_sample_and_external_sources_are_disabled(client):
    response = client.post("/api/v1/projects", headers=ADMIN, json={
        "name": "Terraform source regression", "repo_url": "fixture:demo-shop",
        "aws": {"dump": "shared-platform"},
    })
    assert response.status_code == 201, response.text
    project = response.json()
    pid = project["id"]
    assert project["cloud_account"]["dump_ref"] == "terraform"
    cost = client.get(f"/api/v1/projects/{pid}/aws/cost", headers=VIEWER).json()
    assert cost["last_30_days"] == 0 and cost["recommendations"] == [] and cost["errors"]
    assert client.get("/api/v1/aws/dumps", headers=VIEWER).json() == []
    selected = client.put(f"/api/v1/projects/{pid}/aws/source", headers=ADMIN, json={"dump": "demo-shop"})
    uploaded = client.post(f"/api/v1/projects/{pid}/aws/dump", headers=ADMIN,
                           files={"file": ("dump.zip", b"not used", "application/zip")})
    for result in (selected, uploaded):
        assert result.status_code == 422 and result.json()["error"]["code"] == "terraform_only"
