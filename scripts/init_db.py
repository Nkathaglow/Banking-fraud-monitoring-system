"""Create tables + append-only triggers. Run as the DB OWNER (not the runtime role):
    MIGRATION_DATABASE_URL=postgresql://owner:...@host/db python -m scripts.init_db"""
import os

if os.environ.get("MIGRATION_DATABASE_URL"):
    os.environ["DATABASE_URL"] = os.environ["MIGRATION_DATABASE_URL"]

from src.database import init_db  # noqa: E402

init_db()
print("Schema and append-only triggers are in place.")
