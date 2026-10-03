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
    _ensure_reset_attempts_column()
    _ensure_extension_reports_user_column()
    _ensure_reported_urls_review_columns()
    _ensure_block_detail_columns()


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


def _ensure_reset_attempts_column() -> None:
    """Same self-heal as above, for PasswordResetToken.attempts (added when
    reset switched from an emailed link to an emailed 6-digit code)."""
    if not DB_URL.startswith("sqlite"):
        return
    with engine.connect() as conn:
        cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(password_reset_tokens)")}
        if cols and "attempts" not in cols:
            conn.exec_driver_sql(
                "ALTER TABLE password_reset_tokens ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"
            )
            conn.commit()


def _ensure_extension_reports_user_column() -> None:
    """Same self-heal as above, for ExtensionReport.user_id (who reported
    the URL from a signed-in extension)."""
    if not DB_URL.startswith("sqlite"):
        return
    with engine.connect() as conn:
        cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(extension_reports)")}
        if cols and "user_id" not in cols:
            conn.exec_driver_sql("ALTER TABLE extension_reports ADD COLUMN user_id INTEGER")
            conn.commit()


def _ensure_reported_urls_review_columns() -> None:
    """Same self-heal as above, for ReportedURL.status / reviewed_at (website
    reports now go through the same admin Save / Do Not Save review as
    extension reports). Existing rows start as 'pending': they were never
    actually added to the blocklist, so the admin still has to decide."""
    if not DB_URL.startswith("sqlite"):
        return
    with engine.connect() as conn:
        cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(reported_urls)")}
        if cols and "status" not in cols:
            conn.exec_driver_sql(
                "ALTER TABLE reported_urls ADD COLUMN status VARCHAR(16) "
                "NOT NULL DEFAULT 'pending'"
            )
            conn.commit()
        if cols and "reviewed_at" not in cols:
            conn.exec_driver_sql("ALTER TABLE reported_urls ADD COLUMN reviewed_at DATETIME")
            conn.commit()


def _ensure_block_detail_columns() -> None:
    """Same self-heal: BlockedURL.source/attack_type and
    UserBlockedURL.risk_level/reason (block page details)."""
    if not DB_URL.startswith("sqlite"):
        return
    wanted = {
        "blocked_urls": [("source", "VARCHAR(32)"), ("attack_type", "VARCHAR(64)")],
        "user_blocked_urls": [("risk_level", "VARCHAR(8)"), ("reason", "TEXT")],
    }
    with engine.connect() as conn:
        for table, columns in wanted.items():
            cols = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            for name, sql_type in columns:
                if cols and name not in cols:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
                    conn.commit()
