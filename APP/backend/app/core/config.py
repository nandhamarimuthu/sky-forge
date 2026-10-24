from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import dotenv_values
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", extra="ignore", case_sensitive=False)

    app_env: Literal["dev", "test", "prod"] = "dev"
    database_url: str = f"sqlite:///{BASE_DIR / 'data' / 'skyforge.db'}"
    data_dir: Path = BASE_DIR / "data"
    fixtures_dir: Path = BASE_DIR / "fixtures"

    # "name:role:token[:projectA|projectB]" entries, comma separated. Roles: admin, engineer, viewer.
    api_tokens: str = ""
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    rate_limit_per_minute: int = 300
    scan_rate_limit_per_minute: int = 10

    # "ollama" runs a local model; "openai" calls the hosted OpenAI API (gpt-4o-mini by default).
    llm_provider: Literal["ollama", "openai"] = "ollama"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "gemma3"
    openai_base_url: str = Field(default="https://api.openai.com/v1", pattern=r"^https://")
    openai_model: str = "gpt-4o-mini"
    # Env var holding the OpenAI API key; the key itself is never stored in settings or returned by the API.
    openai_api_key_env: str = Field(default="OPENAI_API_KEY", pattern=r"^[A-Z][A-Z0-9_]{2,119}$")
    llm_enabled: bool = True
    llm_timeout_s: int = 90

    allowed_git_hosts: str = "github.com,gitlab.com,bitbucket.org"
    # Env var holding a GitHub token used to push fix branches / open draft PRs (projects may override per repo).
    github_token_env: str = Field(default="GITHUB_TOKEN", pattern=r"^[A-Z][A-Z0-9_]{2,119}$")
    github_api_url: str = Field(default="https://api.github.com", pattern=r"^https://")
    # GitHub App auth (preferred over a PAT when set): short-lived installation tokens are minted on demand.
    github_app_id: str = ""
    github_app_installation_id: str = ""
    github_app_private_key_path: Path | None = None
    # Alternative to the path: env var holding the PEM contents.
    github_app_private_key_env: str = Field(default="GITHUB_APP_PRIVATE_KEY", pattern=r"^[A-Z][A-Z0-9_]{2,119}$")
    max_repo_mb: int = 300
    clone_timeout_s: int = 180
    agent_timeout_s: int = 900
    max_concurrent_scans: int = 2

    sandbox_enabled: bool = True
    sandbox_python_image: str = "python:3.11-slim"
    sandbox_node_image: str = "node:22-slim"
    sandbox_timeout_s: int = 600
    sandbox_memory: str = "1g"
    sandbox_cpus: str = "1.5"

    osv_api_url: str = "https://api.osv.dev"
    osv_timeout_s: int = 20

    aws_mode: Literal["dump", "live"] = "dump"
    aws_profile: str | None = None
    aws_region: str = "eu-west-2"
    aws_region_allowlist: str = "eu-west-2,eu-west-1,us-east-1"
    aws_service_allowlist: str = "ec2,ebs,rds,s3,lambda,elb,natgateway,cloudwatch,ce"

    max_findings_per_agent: int = Field(default=200, ge=1)

    @field_validator("data_dir", "fixtures_dir", mode="after")
    @classmethod
    def _absolute(cls, v: Path) -> Path:
        return v if v.is_absolute() else (BASE_DIR / v).resolve()

    @field_validator("github_app_private_key_path", mode="after")
    @classmethod
    def _absolute_optional(cls, v: Path | None) -> Path | None:
        return None if v is None else (v if v.is_absolute() else (BASE_DIR / v).resolve())

    @property
    def github_app_configured(self) -> bool:
        return bool(self.github_app_id and self.github_app_installation_id)

    @staticmethod
    def _csv(value: str) -> list[str]:
        return [v.strip() for v in value.split(",") if v.strip()]

    @property
    def git_hosts(self) -> list[str]:
        return self._csv(self.allowed_git_hosts)

    @property
    def cors_list(self) -> list[str]:
        return self._csv(self.cors_origins)

    @property
    def region_allowlist(self) -> list[str]:
        return self._csv(self.aws_region_allowlist)

    @property
    def service_allowlist(self) -> list[str]:
        return self._csv(self.aws_service_allowlist)

    @property
    def workspaces_dir(self) -> Path:
        return self.data_dir / "workspaces"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    s.workspaces_dir.mkdir(parents=True, exist_ok=True)
    s.artifacts_dir.mkdir(parents=True, exist_ok=True)
    return s


def secret_from_env(name: str | None) -> str | None:
    """Resolve a secret reference from the process environment, falling back to the .env file."""
    if not name:
        return None
    value = os.environ.get(name)
    if value is None and (BASE_DIR / ".env").is_file():
        value = dotenv_values(BASE_DIR / ".env").get(name)
    return value or None
