"""Convert post date to published_on

Revision ID: 0f7819a65776
Revises: 696bbb6e53c6
Create Date: 2026-10-06 12:03:06.347551

"""
from alembic import op
from datetime import datetime

import sqlalchemy as sa


revision = '0f7819a65776'
down_revision = '696bbb6e53c6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('blog_posts', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                'published_on',
                sa.Date(),
                nullable=True,
            )
        )

    connection = op.get_bind()

    results = connection.execute(sa.text("SELECT id, date FROM blog_posts")).fetchall()

    for row in results:
        post_id = row[0]
        old_date_str = row[1]

        if not old_date_str:
            raise RuntimeError(
                f"Missing date for blog post id {post_id}"
            )
        try:
            parsed_date = datetime.strptime(old_date_str, "%B %d, %Y").date()
        except ValueError as exc:
            raise RuntimeError(
                f"Could not parse date for blog post id {post_id}: {old_date_str!r}"
            ) from exc

        connection.execute(
            sa.text("UPDATE blog_posts SET published_on = :new_date WHERE id = :post_id"),
            {"new_date": parsed_date, "post_id": post_id}
        )


    with op.batch_alter_table("blog_posts", schema=None) as batch_op:
        batch_op.alter_column(
            'published_on',
            nullable=False
        )
        batch_op.drop_column('date')


def downgrade():
    with op.batch_alter_table('blog_posts', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                'date',
                sa.VARCHAR(length=250),
                autoincrement=False,
                nullable=True,
            )
        )

    connection = op.get_bind()

    posts = sa.table(
        "blog_posts",
        sa.column("id", sa.Integer),
        sa.column("published_on", sa.Date),
    )

    results = connection.execute(
        sa.select(posts.c.id, posts.c.published_on)
    ).fetchall()

    for post_id, published_on in results:
        date_str = published_on.strftime("%B %d, %Y")

        connection.execute(
            sa.text("UPDATE blog_posts SET date = :old_date WHERE id = :post_id"),
            {"old_date": date_str, "post_id": post_id}
        )

    with op.batch_alter_table('blog_posts', schema=None) as batch_op:
        batch_op.alter_column(
            'date',
            nullable=False
        )
        batch_op.drop_column('published_on')
