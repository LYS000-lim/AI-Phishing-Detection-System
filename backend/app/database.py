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
    _ensure_detections_attack_type_column()
    _ensure_detections_source_column()
    _ensure_users_login_activity_columns()


def _ensure_detections_attack_type_column() -> None:
    """create_all() only creates missing TABLES, never adds a missing
    COLUMN to a table that already exists on disk. Detection.attack_type
    was added after this project's dev DBs already had a `detections`
    table, so self-heal it here -- a lightweight stand-in for a real
    migration tool, which this project doesn't otherwise use."""
    if not DB_URL.startswith("sqlite"):
        return
    with engine.connect() as conn:
        cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(detections)")}
        if cols and "attack_type" not in cols:
            conn.exec_driver_sql("ALTER TABLE detections ADD COLUMN attack_type VARCHAR(64)")
            conn.commit()


def _ensure_detections_source_column() -> None:
    """Same self-heal as above, for Detection.source (website vs
    extension), added after existing dev DBs already had this table."""
    if not DB_URL.startswith("sqlite"):
        return
    with engine.connect() as conn:
        cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(detections)")}
        if cols and "source" not in cols:
            conn.exec_driver_sql(
                "ALTER TABLE detections ADD COLUMN source VARCHAR(16) "
                "NOT NULL DEFAULT 'website'"
            )
            conn.commit()


def _ensure_users_login_activity_columns() -> None:
    """Same self-heal as above, for User.last_login_at / last_logout_at."""
    if not DB_URL.startswith("sqlite"):
        return
    with engine.connect() as conn:
        cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(users)")}
        if cols and "last_login_at" not in cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN last_login_at DATETIME")
            conn.commit()
        if cols and "last_logout_at" not in cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN last_logout_at DATETIME")
            conn.commit()
