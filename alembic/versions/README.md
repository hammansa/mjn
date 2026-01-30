This folder will contain alembic revision files after you run:

alembic revision --autogenerate -m "initial"

Then apply migrations with:

alembic upgrade head
