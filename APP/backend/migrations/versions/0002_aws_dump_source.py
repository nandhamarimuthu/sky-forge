"""AWS data-dump source for cloud accounts

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("cloud_account_references") as batch:
        batch.add_column(sa.Column("dump_ref", sa.String(length=200), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("cloud_account_references") as batch:
        batch.drop_column("dump_ref")
