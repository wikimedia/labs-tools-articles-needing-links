"""empty message

Revision ID: 6586de0b2c1a
Revises: 5f490bd0d9be
Create Date: 2020-04-15 13:26:18.408405

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6586de0b2c1a'
down_revision = '5f490bd0d9be'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('wiki', sa.Column('excluded_articles', sa.Text(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('wiki', 'excluded_articles')
    # ### end Alembic commands ###
