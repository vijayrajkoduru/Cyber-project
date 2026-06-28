"""initial schema: users + scan_usage

Revision ID: 0001
Revises:
Create Date: 2026-06-27

Mirrors the bootstrap DDL in tools/auth/_db.py. In production, run
`alembic upgrade head`; the app's idempotent _ensure_schema() is a
safety net that no-ops once these tables exist.
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("username", sa.Text, nullable=False, unique=True),
        sa.Column("email", sa.Text, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.Text, server_default="user"),
        sa.Column("plan", sa.Text, server_default="trial"),
        sa.Column("status", sa.Text, server_default="active"),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("updated_at", sa.Text),
        sa.Column("plan_expires_at", sa.Text),
    )
    op.create_index("idx_username", "users", ["username"])
    op.create_index("idx_email", "users", ["email"])

    op.create_table(
        "scan_usage",
        sa.Column("user_id", sa.Text, nullable=False),
        sa.Column("day", sa.Text, nullable=False),
        sa.Column("count", sa.Integer, nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("user_id", "day"),
    )


def downgrade():
    op.drop_table("scan_usage")
    op.drop_index("idx_email", table_name="users")
    op.drop_index("idx_username", table_name="users")
    op.drop_table("users")
