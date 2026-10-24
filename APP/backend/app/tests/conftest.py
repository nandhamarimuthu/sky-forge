from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="skyforge-test-"))
os.environ.update({
    "APP_ENV": "test",
    "DATABASE_URL": f"sqlite:///{_TMP / 'test.db'}",
    "DATA_DIR": str(_TMP / "data"),
    "API_TOKENS": "alice:admin:admin-token-123456,eve:viewer:viewer-token-123456,bob:engineer:engineer-token-123,"
                  "carol:engineer:scoped-token-1234:Other Project",
    "SANDBOX_ENABLED": "false",
    "LLM_ENABLED": "false",
    "OSV_API_URL": "http://osv.invalid",
    "RATE_LIMIT_PER_MINUTE": "5000",
    # Keep tests hermetic: ignore any GitHub App configured in the developer's .env.
    "GITHUB_APP_ID": "",
    "GITHUB_APP_INSTALLATION_ID": "",
})

import pytest  # noqa: E402

from app.adapters.repository.git_repo import RepoWorkspace, materialize, parse_repo_url  # noqa: E402
from app.adapters.scanners.osv import Advisory  # noqa: E402
from app.core.config import get_settings  # noqa: E402

ADMIN = {"Authorization": "Bearer admin-token-123456"}
VIEWER = {"Authorization": "Bearer viewer-token-123456"}
ENGINEER = {"Authorization": "Bearer engineer-token-123"}
SCOPED = {"Authorization": "Bearer scoped-token-1234"}


class FakeOSV:
    """Deterministic OSV stand-in: old versions of a few packages are vulnerable."""

    VULNERABLE = {("PyPI", "requests"): ("2.31.0", "high"), ("PyPI", "urllib3"): ("1.26.18", "medium"),
                  ("PyPI", "flask"): ("2.2.5", "high"), ("PyPI", "werkzeug"): ("2.2.3", "high")}

    def query(self, name: str, ecosystem: str, version: str) -> list[Advisory]:
        from packaging.version import Version

        hit = self.VULNERABLE.get((ecosystem, name.lower()))
        if not hit or Version(version) >= Version(hit[0]):
            return []
        return [Advisory(id=f"GHSA-test-{name.lower()}", aliases=[f"CVE-2099-{len(name)}"], summary=f"{name} issue",
                         severity=hit[1], cvss_score=None, fixed_versions=[hit[0]], references=[], published=None)]


@pytest.fixture(scope="session")
def settings():
    return get_settings()


@pytest.fixture(scope="session")
def fixture_ws(settings, tmp_path_factory) -> RepoWorkspace:
    dest = tmp_path_factory.mktemp("ws") / "repo"
    ref = parse_repo_url("fixture:demo-shop", settings.git_hosts, settings.fixtures_dir)
    materialize(ref, dest, branch=None, fixtures_dir=settings.fixtures_dir, timeout=60, max_mb=50)
    return RepoWorkspace(dest)


@pytest.fixture(scope="session")
def client(settings):
    from fastapi.testclient import TestClient

    from app.main import app
    from app.services.container import build_container, set_container

    c = build_container(settings)
    fake = FakeOSV()
    c.osv = fake  # type: ignore[assignment]
    c.orchestrator.osv = fake  # type: ignore[assignment]
    set_container(c)
    with TestClient(app) as tc:
        yield tc


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001
    shutil.rmtree(_TMP, ignore_errors=True)
