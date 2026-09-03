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

    detections = relationship(
        "Detection", back_populates="user",
        cascade="all, delete-orphan", passive_deletes=True,
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
    ip_address = Column(String(64), nullable=True)
    created_at = Column(
        DateTime, nullable=False, default=_utc_now, index=True,
    )

    user = relationship("User", back_populates="detections")
