from datetime import datetime, timezone


def _utc_now():
    """Naive UTC 'now' for DB timestamps (stored as naive to keep SQLite happy)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text,
)
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(120), nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), nullable=False, default="user")   # "user" | "admin"
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=_utc_now)
    last_login_at = Column(DateTime, nullable=True)
    last_logout_at = Column(DateTime, nullable=True)

    detections = relationship(
        "Detection",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    reported_urls = relationship(
        "ReportedURL",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    url = Column(Text, nullable=False)
    prediction = Column(String(16), nullable=False)   # "legitimate" | "phishing"
    label = Column(Integer, nullable=False)           # 0 = Legit, 1 = Phish
    confidence = Column(Float, nullable=False)        # 0..1 confidence in prediction
    phishing_probability = Column(Float, nullable=False)
    risk_level = Column(String(8), nullable=False)    # "Low" | "Medium" | "High"
    model_used = Column(String(64), nullable=False)   # e.g. "RandomForest"
    attack_type = Column(String(64), nullable=True)   # e.g. "Credential Theft"; null for legitimate
    ip_address = Column(String(64), nullable=True)
    source = Column(String(16), nullable=False, default="website")  # "website" | "extension"
    created_at = Column(
        DateTime, nullable=False, default=_utc_now, index=True,
    )

    user = relationship("User", back_populates="detections")

class ReportedURL(Base):
    __tablename__ = "reported_urls"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    url = Column(
        Text,
        nullable=False,
    )

    attack_type = Column(
        String(64),
        nullable=True,
    )

    detection_reason = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=_utc_now,
        index=True,
    )

    user = relationship(
        "User",
        back_populates="reported_urls",
    )

class ExtensionReport(Base):
    __tablename__ = "extension_reports"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    url = Column(
        Text,
        nullable=False,
    )

    attack_type = Column(
        String(64),
        nullable=True,
    )

    detection_reason = Column(
        Text,
        nullable=True,
    )

    ip_address = Column(
        String(64),
        nullable=True,
    )

    browser_info = Column(
        Text,
        nullable=True,
    )

    status = Column(
        String(16),
        nullable=False,
        default="pending",
    )
    # pending | approved | rejected

    created_at = Column(
        DateTime,
        nullable=False,
        default=_utc_now,
        index=True,
    )

    reviewed_at = Column(
        DateTime,
        nullable=True,
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=_utc_now)


class BlockedURL(Base):
    __tablename__ = "blocked_urls"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    url = Column(
        Text,
        nullable=False,
    )

    domain = Column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )

    risk_level = Column(
        String(8),
        nullable=False,
        default="High",
    )

    reason = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=_utc_now,
        index=True,
    )