from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from app.core.config import BASE_DIR, get_settings


def alembic_config() -> Config:
    cfg = Config(str(BASE_DIR / "backend" / "alembic.ini"))
    cfg.set_main_option("script_location", str(BASE_DIR / "backend" / "migrations"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    return cfg


def upgrade_database() -> None:
    Path(get_settings().data_dir).mkdir(parents=True, exist_ok=True)
    command.upgrade(alembic_config(), "head")
