<%!
from alembic import op
import sqlalchemy as sa
%>
"""Revision script
"""

revision = '${up_revision}'
down_revision = ${repr(down_revision)}
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
% if upgrade_ops:
${upgrade_ops}
% else:
    pass
% endif


def downgrade():
% if downgrade_ops:
${downgrade_ops}
% else:
    pass
% endif
