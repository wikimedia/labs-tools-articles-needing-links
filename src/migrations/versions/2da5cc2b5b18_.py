"""empty message

Revision ID: 2da5cc2b5b18
Revises: fe1fb94c885d
Create Date: 2020-04-03 16:45:58.461263

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2da5cc2b5b18'
down_revision = 'fe1fb94c885d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('wiki', sa.Column('url', sa.String(length=255), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('wiki', 'url')
    # ### end Alembic commands ###
