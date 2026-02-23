from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class LogUpload(Base):
    __tablename__ = "log_uploads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    total_lines: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    events: Mapped[list["SuspiciousEvent"]] = relationship(
        "SuspiciousEvent", back_populates="upload", cascade="all, delete-orphan"
    )
    analysis: Mapped[AIAnalysis | None] = relationship(
        "AIAnalysis", back_populates="upload", uselist=False, cascade="all, delete-orphan"
    )


class SuspiciousEvent(Base):
    __tablename__ = "suspicious_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    upload_id: Mapped[int] = mapped_column(Integer, ForeignKey("log_uploads.id", ondelete="CASCADE"), nullable=False)

    timestamp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)

    rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_weight: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_message: Mapped[str] = mapped_column(Text, nullable=False)

    upload: Mapped["LogUpload"] = relationship("LogUpload", back_populates="events")


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    upload_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("log_uploads.id", ondelete="CASCADE"), nullable=False, unique=True
    )

    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(128), nullable=False)
    mitre_techniques: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_score: Mapped[int] = mapped_column(Integer, nullable=False)
    analysis_summary: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_actions: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    upload: Mapped["LogUpload"] = relationship("LogUpload", back_populates="analysis")
