"""Add request_type column

Revision ID: 188ec4536243
Revises: 868fa3de91cc
Create Date: 2025-06-05 03:40:21.110695

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '188ec4536243'
down_revision = '868fa3de91cc'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('schedule_request', schema=None) as batch_op:
        batch_op.add_column(sa.Column('request_type', sa.String(length=50), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('schedule_request', schema=None) as batch_op:
        batch_op.drop_column('request_type')

    # ### end Alembic commands ###
