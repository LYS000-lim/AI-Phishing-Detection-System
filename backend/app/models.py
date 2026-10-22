from datetime import datetime, timezone


def _utc_now():
    """Naive UTC 'now' for DB timestamps (stored as naive to keep SQLite happy)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint,
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
    # The score and confidence the result page showed (score_view.py, always
    # in the verdict's band); null for records saved before 2026-10-21.
    risk_score = Column(Float, nullable=True)
    score_confidence = Column(Float, nullable=True)
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

    # Admin review, same as ExtensionReport: pending until the admin picks
    # "Save in Database" (approved -> added to BlockedURL) or "Do Not Save"
    # (row deleted).
    status = Column(
        String(16),
        nullable=False,
        default="pending",
    )

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

    # Set when the extension is signed in to a website account, so the
    # admin can see who reported/blocked it (NULL = anonymous).
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    user = relationship("User")

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
    # sha256 of "<user_id>:<6-digit code>" - the emailed reset code.
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    # Wrong-code guesses; the code is burned after MAX_CODE_ATTEMPTS.
    attempts = Column(Integer, nullable=False, default=0)
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

    # Where the approved report came from ("Chrome Extension" or
    # "PhishGuard Website") and its attack category, so the extension's
    # block page can say who blocked the site and why.
    source = Column(
        String(32),
        nullable=True,
    )

    attack_type = Column(
        String(64),
        nullable=True,
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=_utc_now,
        index=True,
    )

class UserBlockedURL(Base):
    """A website a signed-in user blocked from the extension's warning page
    ("Block URL"). Stored per user so the block follows their account (any
    browser they sign the extension into) and they can review/unblock it on
    the website's Browser Extension page. Matched by hostname, like the
    extension's local block list."""
    __tablename__ = "user_blocked_urls"
    __table_args__ = (UniqueConstraint("user_id", "hostname", name="uq_user_blocked_host"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(Text, nullable=False)
    hostname = Column(String(255), nullable=False, index=True)
    attack_type = Column(String(64), nullable=True)
    # Scan result at the moment the user clicked "Block URL" (shown on the
    # extension's block page).
    risk_level = Column(String(8), nullable=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=_utc_now, index=True)

    user = relationship("User")
