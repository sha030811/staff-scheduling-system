"""Add created_at default

Revision ID: 0fe9958fcbf8
Revises: 
Create Date: 2025-06-02 02:01:31.888727

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '0fe9958fcbf8'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('availability', schema=None) as batch_op:
        batch_op.add_column(sa.Column('created_at', sa.DateTime(), nullable=True))
        batch_op.alter_column('date',
               existing_type=sa.DATE(),
               type_=sa.String(length=50),
               existing_nullable=True)
        batch_op.alter_column('time_of_day',
               existing_type=mysql.VARCHAR(length=20),
               type_=sa.String(length=10),
               existing_nullable=True)

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('role',
               existing_type=mysql.VARCHAR(length=20),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('role',
               existing_type=mysql.VARCHAR(length=20),
               nullable=False)

    with op.batch_alter_table('availability', schema=None) as batch_op:
        batch_op.alter_column('time_of_day',
               existing_type=sa.String(length=10),
               type_=mysql.VARCHAR(length=20),
               existing_nullable=True)
        batch_op.alter_column('date',
               existing_type=sa.String(length=50),
               type_=sa.DATE(),
               existing_nullable=True)
        batch_op.drop_column('created_at')

    # ### end Alembic commands ###
