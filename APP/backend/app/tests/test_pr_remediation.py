from __future__ import annotations

import httpx
import pytest

from app.adapters.repository.git_repo import RepoWorkspace, run_git
from app.adapters.repository.patches import PatchReconstructionError, restore_patch_context
from app.adapters.scanners.manifests import unified_diff
from app.core.security import redact
from app.db.session import session_scope
from app.models import Finding, RemediationProposal, Scan
from app.orchestration.orchestrator import workspace_dir
from app.services import publish
from app.tests.conftest import ENGINEER, VIEWER
from app.tests.test_api import _wait_pull_request

TF_SOURCE = '''resource "aws_db_instance" "main" {
  identifier = "example"
  password = "example-password-for-tests"
  instance_class = "db.r5.2xlarge"
  storage_encrypted = false
}
'''


@pytest.mark.parametrize("ending", ["\n", "\r\n", ""])
def test_restore_only_context_and_removed_lines(tmp_path, ending):
    before = TF_SOURCE.rstrip("\n").replace("\n", "\r\n" if ending == "\r\n" else "\n") + ending
    after = before.replace("storage_encrypted = false", "storage_encrypted = true")
    (tmp_path / "db.tf").write_bytes(before.encode())
    patch = unified_diff("db.tf", before, after)
    stored = redact(patch)
    assert stored != patch and "example-password-for-tests" not in stored
    assert restore_patch_context(RepoWorkspace(tmp_path), stored) == patch
    assert "example-password-for-tests" not in stored


def test_redacted_patch_refuses_stale_context_and_redacted_additions(tmp_path):
    path = tmp_path / "db.tf"
    path.write_text(TF_SOURCE)
    patch = redact(unified_diff("db.tf", TF_SOURCE, TF_SOURCE.replace("false", "true")))
    path.write_text(TF_SOURCE.replace('identifier = "example"', 'identifier = "changed"'))
    with pytest.raises(PatchReconstructionError, match="context changed"):
        restore_patch_context(RepoWorkspace(tmp_path), patch)
    path.write_text(TF_SOURCE)
    unsafe = redact(unified_diff("db.tf", TF_SOURCE, TF_SOURCE.replace("example-password-for-tests", "another-test-secret")))
    with pytest.raises(PatchReconstructionError, match="added line is redacted"):
        restore_patch_context(RepoWorkspace(tmp_path), unsafe)


def _proposal(client, settings, agent, kind, source, after, rel):
    before_files = source if isinstance(source, dict) else {rel: source}
    after_files = after if isinstance(after, dict) else {rel: after}
    agent_id = "code_health" if agent == "code_health_js" else agent
    response = client.post("/api/v1/projects", headers=ENGINEER, json={
        "name": f"PR pipeline {agent}", "repo_url": f"https://github.com/example/{agent}",
    })
    assert response.status_code == 201, response.text
    project_id = response.json()["id"]
    with session_scope() as db:
        scan = Scan(project_id=project_id, status="completed", requested_by="bob")
        db.add(scan)
        db.flush()
        root = workspace_dir(settings, project_id, scan.id) / "repo"
        root.mkdir(parents=True)
        for path, content in before_files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(content)
        run_git(["init", "-q"], cwd=root)
        run_git(["add", "."], cwd=root)
        run_git(["-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "-qm", "Initial source"], cwd=root)
        scan.commit_sha = run_git(["rev-parse", "HEAD"], cwd=root)
        finding = Finding(id=f"finding-{agent}", project_id=project_id, scan_id=scan.id, first_scan_id=scan.id,
                          fingerprint=agent, source_agent=agent_id, category="code_health" if kind == "refactor" else "iac",
                          rule_id="health:autofix" if kind == "refactor" else "iac:rds-encryption", severity="low",
                          title="Pipeline regression", target=rel)
        db.add(finding)
        db.flush()
        diff = "".join(unified_diff(path, before_files[path], after_files[path]) for path in sorted(before_files))
        prop = RemediationProposal(finding_id=finding.id, project_id=project_id, scan_id=scan.id, agent_id=agent_id,
                                   kind=kind, title="Safe source change", files=sorted(before_files),
                                   diff=redact(diff), status="rejected_by_policy",
                                   validation={"passed": False, "checks": [
                                       {"name": "applies_cleanly", "passed": False, "detail": "old redaction failure"}]})
        db.add(prop)
        db.flush()
        return finding.id, prop.id, root


@pytest.mark.parametrize("agent", ["aws_optimizer", "guardrails", "code_health", "code_health_js"])
def test_rejected_proposal_revalidates_applies_and_opens_app_pr(client, settings, monkeypatch, agent):
    if agent == "code_health_js":
        from app.adapters.scanners.js_refactor import aggregation_refactor
        from app.tests.test_code_health_pr import sources

        source = sources()
        plan = aggregation_refactor(source)
        assert plan
        after, kind, rel = plan.changes, "refactor", "src/services/shippingCarrier.js"
    elif agent == "code_health":
        source, after, kind, rel = "import json\nvalue = 1\n", "value = 1\n", "refactor", "module.py"
    else:
        source = TF_SOURCE
        after = (source.replace("db.r5.2xlarge", "db.r5.xlarge") if agent == "aws_optimizer"
                 else source.replace("storage_encrypted = false", "storage_encrypted = true"))
        kind, rel = "iac_change", "database.tf"
    fid, pid, root = _proposal(client, settings, agent, kind, source, after, rel)
    requests = []
    pushes = []
    monkeypatch.setattr(publish, "publish_enabled", lambda c: True)
    monkeypatch.setattr(publish, "_token", lambda c, project: ("test-installation-token", "test-app[bot]"))
    monkeypatch.setattr(publish, "can_push", lambda settings: True)

    def call(self, method, path, **kwargs):
        requests.append((method, path))
        if method == "GET" and path == f"/repos/example/{agent}":
            return httpx.Response(200, json={"default_branch": "main", "permissions": {"push": False}})
        if method == "POST" and path == f"/repos/example/{agent}/pulls":
            assert kwargs["json"]["draft"] is True
            assert kwargs["json"]["head"].startswith("skyforge/")
            assert "example-password-for-tests" not in kwargs["json"]["body"]
            return httpx.Response(201, json={"html_url": f"https://github.com/example/{agent}/pull/1", "number": 1})
        raise AssertionError(f"Unexpected GitHub request: {method} {path}")

    monkeypatch.setattr(publish._GitHub, "call", call)
    monkeypatch.setattr(publish, "run_git", lambda args, **kwargs: pushes.append(args))
    assert client.post(f"/api/v1/findings/{fid}/fix", headers=VIEWER, json={"proposal_id": pid}).status_code == 403
    response = client.post(f"/api/v1/findings/{fid}/fix", headers=ENGINEER, json={"proposal_id": pid})
    assert response.status_code == 202, response.text
    final = _wait_pull_request(client, fid, pid)
    assert final["status"] == "verified", final
    assert final["verification"]["pull_request"]["mode"] == "direct"
    assert len(pushes) == 1 and pushes[0][0] == "push"
    assert len(requests) == 2
    worktree = settings.data_dir / final["verification"]["worktree"]
    before_files = source if isinstance(source, dict) else {rel: source}
    after_files = after if isinstance(after, dict) else {rel: after}
    for path, content in before_files.items():
        assert (root / path).read_text() == content
        assert (worktree / path).read_text() == after_files[path]
    assert not (worktree.parent / f"{pid}.patch").exists()
    assert "example-password-for-tests" not in final["diff"]


def test_recheck_does_not_bypass_policy(client, settings, monkeypatch):
    fid, pid, _ = _proposal(client, settings, "unsafe", "refactor", "value = 1\n",
                           "import subprocess\nsubprocess.run('sh', shell=True)\n", "module.py")
    monkeypatch.setattr(publish, "publish_enabled", lambda c: True)
    response = client.post(f"/api/v1/findings/{fid}/fix", headers=ENGINEER, json={"proposal_id": pid})
    assert response.status_code == 422 and response.json()["error"]["code"] == "policy_violation"
    detail = client.get(f"/api/v1/findings/{fid}", headers=VIEWER).json()
    assert detail["proposals"][0]["status"] == "rejected_by_policy"
    assert not detail["approvals"]
