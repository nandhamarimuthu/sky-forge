from __future__ import annotations

from pathlib import Path

import pytest

from app.adapters.repository.git_repo import RepositoryError, parse_repo_url
from app.core.config import Settings
from app.core.security import PathEscapeError, TokenRegistry, redact, safe_join


def test_safe_join_blocks_traversal(tmp_path: Path):
    (tmp_path / "a").mkdir()
    assert safe_join(tmp_path, "a/b.txt") == (tmp_path / "a" / "b.txt").resolve()
    for bad in ("../etc/passwd", "/etc/passwd", "a/../../x", "", "a\x00b"):
        with pytest.raises(PathEscapeError):
            safe_join(tmp_path, bad)


def test_safe_join_blocks_symlink_escape(tmp_path: Path):
    outside = tmp_path.parent / "outside-target"
    outside.mkdir(exist_ok=True)
    (tmp_path / "link").symlink_to(outside)
    with pytest.raises(PathEscapeError):
        safe_join(tmp_path, "link/file")


def test_redact_masks_secrets():
    text = "key AKIAIOSFODNN7EXAMPLE and password = 'Xk9#mQ2vLp7$Rt4w' Authorization: Bearer abc.def"
    out = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "Xk9#mQ2vLp7" not in out
    assert "abc.def" not in out


def test_token_registry_roles_and_scopes():
    s = Settings(api_tokens="a:admin:aaaaaaaaaaaaaaa,v:viewer:vvvvvvvvvvvvvvv:proj1|proj2", app_env="test")
    reg = TokenRegistry(s)
    admin, viewer = reg.resolve("aaaaaaaaaaaaaaa"), reg.resolve("vvvvvvvvvvvvvvv")
    assert admin and admin.can("settings:write")
    assert viewer and not viewer.can("scan:run") and viewer.can("read")
    assert viewer.can_access_project("proj1") and not viewer.can_access_project("proj3")
    assert reg.resolve("wrong") is None and reg.resolve(None) is None


def test_token_registry_refuses_placeholder_in_prod():
    with pytest.raises(RuntimeError):
        TokenRegistry(Settings(api_tokens="a:admin:change-me-please-now", app_env="prod"))
    with pytest.raises(RuntimeError):
        TokenRegistry(Settings(api_tokens="", app_env="prod"))


@pytest.mark.parametrize("url", [
    "http://github.com/a/b", "https://evil.com/a/b", "https://user:pw@github.com/a/b", "https://github.com/a",
    "https://github.com/a/b?x=1", "https://github.com/../b", "fixture:../etc", "file:///etc/passwd",
    "https://github.com:8443/a/b", "git@github.com:a/b.git",
])
def test_parse_repo_url_rejects(url: str, settings):
    with pytest.raises((RepositoryError, PathEscapeError)):
        parse_repo_url(url, settings.git_hosts, settings.fixtures_dir)


def test_parse_repo_url_accepts(settings):
    ref = parse_repo_url("https://www.github.com/pallets/flask.git", settings.git_hosts, settings.fixtures_dir)
    assert (ref.provider, ref.owner, ref.name, ref.url) == ("github", "pallets", "flask",
                                                             "https://github.com/pallets/flask")
