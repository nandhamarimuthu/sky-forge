"""Drop the project environment field

Revision ID: 0003
Revises: 0002
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("projects") as batch:
        batch.drop_column("environment")


def downgrade() -> None:
    with op.batch_alter_table("projects") as batch:
        batch.add_column(sa.Column("environment", sa.String(length=20), nullable=False, server_default="prod"))
