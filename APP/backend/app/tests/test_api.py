from __future__ import annotations

import json
import time

import httpx

from app.tests.conftest import ADMIN, ENGINEER, SCOPED, VIEWER


def _wait_scan(client, scan_id: str, timeout: float = 120) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get(f"/api/v1/scans/{scan_id}", headers=ADMIN).json()
        if s["status"] in ("completed", "partial", "failed", "cancelled"):
            return s
        time.sleep(0.5)
    raise AssertionError("scan did not finish")


def _wait_proposal(client, finding_id: str, proposal_id: str, timeout: float = 60) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        d = client.get(f"/api/v1/findings/{finding_id}", headers=ADMIN).json()
        p = next(x for x in d["proposals"] if x["id"] == proposal_id)
        if p["status"] not in ("approved", "applying") and (p["verification"] or {}).get("status") != "running":
            return p
        time.sleep(0.3)
    raise AssertionError("remediation did not finish")


def _check_pull_request(client, fid: str, pid: str, monkeypatch) -> None:
    from app.services import publish

    token = "ghp_" + "x" * 36
    url = f"/api/v1/findings/{fid}/pull-request"
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert client.post(url, headers=VIEWER, json={"proposal_id": pid}).status_code == 403
    r = client.post(url, headers=ENGINEER, json={"proposal_id": pid})
    assert r.status_code == 422 and r.json()["error"]["code"] == "github_token_missing"

    monkeypatch.setenv("GITHUB_TOKEN", token)
    created: list[bool] = []

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["authorization"] == f"Bearer {token}"
        path = req.url.path
        if path == "/user":
            return httpx.Response(200, json={"login": "octo"})
        if path == "/repos/octo/skyforge-demo-shop" and req.method == "GET":
            return httpx.Response(200 if created else 404, json={"default_branch": "main"})
        if path == "/user/repos":
            assert json.loads(req.content)["private"] is True
            created.append(True)
            return httpx.Response(201, json={})
        if path == "/repos/octo/skyforge-demo-shop/pulls" and req.method == "POST":
            body = json.loads(req.content)
            assert body["draft"] is True and body["head"].startswith("skyforge/fix-")
            assert token not in body["body"]
            return httpx.Response(201, json={"html_url": "https://github.com/octo/skyforge-demo-shop/pull/1",
                                             "number": 1, "draft": True})
        return httpx.Response(500, json={"message": f"unexpected {req.method} {path}"})

    real_init = publish._GitHub.__init__

    def init(self, api, tok):
        real_init(self, api, tok)
        self.client = httpx.Client(base_url=api, headers=self.client.headers, transport=httpx.MockTransport(handler))

    pushes: list[tuple[list[str], str | None]] = []
    monkeypatch.setattr(publish._GitHub, "__init__", init)
    monkeypatch.setattr(publish.time, "sleep", lambda _s: None)
    monkeypatch.setattr(publish, "run_git",
                        lambda args, cwd=None, timeout=60, token=None: pushes.append((args, token)))

    r = client.post(url, headers=ENGINEER, json={"proposal_id": pid})
    assert r.status_code == 200, r.text
    pr = r.json()
    assert pr["number"] == 1 and pr["mode"] == "sample-repo"
    (args, used_token), = pushes
    assert args[0] == "push" and "--force" not in args and "-f" not in args
    assert "https://github.com/octo/skyforge-demo-shop.git" in args and used_token == token
    assert any(a.endswith(":refs/heads/" + pr["branch"]) for a in args)
    # Idempotent: a second click returns the same PR without pushing again.
    assert client.post(url, headers=ENGINEER, json={"proposal_id": pid}).json()["url"] == pr["url"]
    assert len(pushes) == 1
    detail = client.get(f"/api/v1/findings/{fid}", headers=VIEWER).json()
    assert detail["proposals"][0]["verification"]["pull_request"]["number"] == 1


def test_health_is_public(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["database"] is True


def test_auth_required_and_errors_are_structured(client):
    r = client.get("/api/v1/projects")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    r = client.get("/api/v1/projects", headers={"Authorization": "Bearer nope-nope-nope"})
    assert r.status_code == 401


def test_viewer_cannot_create_projects(client):
    r = client.post("/api/v1/projects", headers=VIEWER, json={"name": "X1", "repo_url": "fixture:demo-shop"})
    assert r.status_code == 403


def test_input_validation(client):
    r = client.post("/api/v1/projects", headers=ADMIN, json={"name": "<script>", "repo_url": "fixture:demo-shop"})
    assert r.status_code == 422
    r = client.post("/api/v1/projects", headers=ADMIN, json={"name": "Bad Host", "repo_url": "https://evil.com/a/b"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_repository"


def test_end_to_end_scan_review_and_remediation(client, monkeypatch):
    r = client.post("/api/v1/projects", headers=ENGINEER,
                    json={"name": "Demo Shop", "repo_url": "fixture:demo-shop"})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    assert client.post("/api/v1/projects", headers=ADMIN,
                       json={"name": "demo shop", "repo_url": "fixture:demo-shop"}).status_code == 409

    # Project-scoped principal cannot see it (404, not 403, to avoid leaking existence).
    assert client.get(f"/api/v1/projects/{pid}", headers=SCOPED).status_code == 404

    r = client.post(f"/api/v1/projects/{pid}/scans", headers=ENGINEER, json={"options": {"use_llm": False}})
    assert r.status_code == 202
    scan = _wait_scan(client, r.json()["id"])
    assert scan["status"] in ("completed", "partial"), scan
    statuses = {run["agent_id"]: run["status"] for run in scan["agent_runs"]}
    assert set(statuses) == {"vulnerability", "unit_test", "functional_test", "aws_optimizer", "code_health",
                             "guardrails"}
    assert all(s == "completed" for s in statuses.values()), statuses
    assert scan["summary"]["findings"] > 10

    events = client.get(f"/api/v1/scans/{scan['id']}/events?stream=false", headers=VIEWER).json()
    assert events and events[-1]["data"].get("terminal") is True

    with client.stream("GET", f"/api/v1/scans/{scan['id']}/events", headers=VIEWER) as resp:
        body = "".join(resp.iter_text())
    assert "event: end" in body

    page = client.get(f"/api/v1/findings?project_id={pid}&severity=critical,high&page_size=100", headers=VIEWER).json()
    assert page["total"] > 0 and all(f["severity"] in ("critical", "high") for f in page["items"])
    assert "severity" in page["facets"]

    vuln = client.get(f"/api/v1/findings?project_id={pid}&agent=vulnerability&q=requests", headers=VIEWER).json()
    fid = vuln["items"][0]["id"]
    detail = client.get(f"/api/v1/findings/{fid}", headers=VIEWER).json()
    prop = detail["proposals"][0]
    assert prop["status"] == "validated" and prop["validation"]["passed"]

    # Viewer cannot approve; applying before approval is refused.
    assert client.post(f"/api/v1/findings/{fid}/review", headers=VIEWER,
                       json={"decision": "approve", "proposal_id": prop["id"]}).status_code == 403
    r = client.post(f"/api/v1/findings/{fid}/remediate", headers=ENGINEER, json={"proposal_id": prop["id"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "approval_required"

    r = client.post(f"/api/v1/findings/{fid}/review", headers=ENGINEER,
                    json={"decision": "approve", "proposal_id": prop["id"], "comment": "LGTM"})
    assert r.status_code == 200, r.text
    r = client.post(f"/api/v1/findings/{fid}/remediate", headers=ENGINEER, json={"proposal_id": prop["id"]})
    assert r.status_code == 202
    final = _wait_proposal(client, fid, prop["id"])
    assert final["status"] == "verified", final
    assert final["branch"].startswith("skyforge/fix-") and final["commit_sha"]
    detail = client.get(f"/api/v1/findings/{fid}", headers=VIEWER).json()
    assert detail["status"] == "verified"
    assert [a["decision"] for a in detail["approvals"]] == ["approve"]

    _check_pull_request(client, fid, prop["id"], monkeypatch)

    # Dismiss another finding
    other = page["items"][0]["id"]
    r = client.post(f"/api/v1/findings/{other}/review", headers=ENGINEER, json={"decision": "dismiss"})
    assert r.status_code == 200 and r.json()["status"] == "dismissed"

    arts = client.get(f"/api/v1/scans/{scan['id']}/artifacts", headers=VIEWER).json()
    assert arts
    dl = client.get(f"/api/v1/scans/{scan['id']}/artifacts/{arts[0]['id']}", headers=VIEWER)
    assert dl.status_code == 200 and dl.headers["x-content-type-options"] == "nosniff"

    cost = client.get(f"/api/v1/projects/{pid}/aws/cost", headers=VIEWER).json()
    assert cost["mode"] == "dump" and cost["simulated"] is False and cost["measured_spend"] is True
    assert cost["source"]["dump"] == "demo-shop" and cost["daily_total"] and cost["estimated_monthly_savings"] > 0
    res = client.get(f"/api/v1/projects/{pid}/aws/resources", headers=VIEWER).json()
    assert res["items"] and any(i["iac_address"] == "aws_instance.api" for i in res["items"])
    quality = client.get(f"/api/v1/projects/{pid}/quality", headers=VIEWER).json()
    assert quality["metrics"]["max_complexity"] >= 15

    dash = client.get("/api/v1/dashboard/summary", headers=VIEWER).json()
    assert dash["projects"] >= 1 and dash["open_total"] > 0 and dash["spend_simulated"] is False and dash["spend_30d"] > 1000

    agents = client.get("/api/v1/agents", headers=VIEWER).json()
    assert len(agents) == 6
    runs = client.get("/api/v1/agents/guardrails/runs", headers=VIEWER).json()
    assert runs["total"] >= 1

    # Re-scan: fixed dependency no longer pinned in the base repo, so it is re-detected (regression semantics).
    r = client.post(f"/api/v1/projects/{pid}/scans", headers=ENGINEER,
                    json={"agents": ["vulnerability"], "options": {"use_llm": False}})
    assert r.status_code == 202, r.text
    rescan = _wait_scan(client, r.json()["id"])
    assert rescan["status"] == "completed"


def test_audit_requires_admin_and_records_denials(client):
    assert client.get("/api/v1/audit", headers=VIEWER).status_code == 403
    log = client.get("/api/v1/audit?outcome=denied", headers=ADMIN).json()
    assert log["total"] >= 1
    actions = {e["action"] for e in log["items"]}
    assert "access.denied" in actions or "auth.failed" in actions


def test_settings_update_admin_only(client):
    assert client.put("/api/v1/settings", headers=ENGINEER, json={"ollama_model": "gemma3"}).status_code == 403
    r = client.put("/api/v1/settings", headers=ADMIN, json={"ollama_model": "gemma3:4b", "execute_tests": False})
    assert r.status_code == 200 and r.json()["llm"]["model"] == "gemma3:4b"
    assert r.json()["scan_policy"]["execute_tests"] is False


def test_reset_clears_all_data_admin_only(client, settings):
    client.post("/api/v1/projects", headers=ADMIN, json={"name": "Reset me", "repo_url": "fixture:orders-api"})
    (settings.workspaces_dir / "leftover").mkdir(parents=True, exist_ok=True)
    body = {"confirm": "DELETE ALL DATA"}
    assert client.post("/api/v1/admin/reset", headers=ENGINEER, json=body).status_code == 403
    r = client.post("/api/v1/admin/reset", headers=ADMIN, json={"confirm": "yes"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "confirmation_required"
    r = client.post("/api/v1/admin/reset", headers=ADMIN, json=body)
    assert r.status_code == 200, r.text
    assert client.get("/api/v1/projects", headers=ADMIN).json()["total"] == 0
    assert client.get("/api/v1/findings", headers=ADMIN).json()["total"] == 0
    assert not (settings.workspaces_dir / "leftover").exists()
    # Only the reset itself remains in the audit trail.
    assert [e["action"] for e in client.get("/api/v1/audit", headers=ADMIN).json()["items"]] == ["platform.reset"]
