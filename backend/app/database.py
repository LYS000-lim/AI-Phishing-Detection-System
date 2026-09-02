"""
SQLite database setup for PhishGuard AI.

The DB file lives at backend/phishguard.db by default. Override the
location with the PHISHGUARD_DB environment variable if needed.
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(_HERE, "..", "phishguard.db")
DB_URL = os.environ.get("PHISHGUARD_DB_URL",
                        f"sqlite:///{os.path.abspath(DEFAULT_DB_PATH)}")

engine = create_engine(
    DB_URL,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""


def get_db():
    """FastAPI dependency: yields a session and closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Safe to call multiple times."""
    from . import models  # noqa: F401  (registers ORM classes on Base)
    Base.metadata.create_all(bind=engine)
