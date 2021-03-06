"""empty message

Revision ID: 5f490bd0d9be
Revises: b174cf2bbbd6
Create Date: 2020-04-14 18:25:16.158582

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '5f490bd0d9be'
down_revision = 'b174cf2bbbd6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('suggested_article', 'probability')
    op.add_column('wiki', sa.Column('treshold', sa.Integer(), nullable=True))
    op.drop_column('wiki', 'bytes_per_link_max')
    op.drop_column('wiki', 'bytes_per_link_avg')
    op.drop_column('wiki', 'tolerance')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('wiki', sa.Column('tolerance', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.add_column('wiki', sa.Column('bytes_per_link_avg', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.add_column('wiki', sa.Column('bytes_per_link_max', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    op.drop_column('wiki', 'treshold')
    op.add_column('suggested_article', sa.Column('probability', mysql.INTEGER(display_width=11), autoincrement=False, nullable=True))
    # ### end Alembic commands ###
