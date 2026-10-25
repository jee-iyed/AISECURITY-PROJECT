from datetime import UTC, datetime

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def now():
    return datetime.now(UTC).isoformat()


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    email: Mapped[str] = mapped_column(unique=True)
    hashed_password: Mapped[str]
    role: Mapped[str]


class Student(Base):
    __tablename__ = "students"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)
    class_name: Mapped[str]


class Professor(Base):
    __tablename__ = "professors"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)
    department: Mapped[str]


class Course(Base):
    __tablename__ = "courses"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    professor_id: Mapped[int] = mapped_column(ForeignKey("professors.id"))
    class_name: Mapped[str]
    room: Mapped[str]


class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    course_id: Mapped[int] = mapped_column(ForeignKey("courses.id"))
    day: Mapped[str]
    start_time: Mapped[str]
    end_time: Mapped[str]


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[str] = mapped_column(default=now)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    user_name: Mapped[str]
    role: Mapped[str]
    prompt_preview: Mapped[str] = mapped_column(Text)
    threat_type: Mapped[str | None]
    risk_score: Mapped[int]
    risk_level: Mapped[str]
    decision: Mapped[str]
    tool_name: Mapped[str | None]
    reason: Mapped[str]
    correlation_id: Mapped[str | None]
    source: Mapped[str | None]
    policy_rules: Mapped[str | None] = mapped_column(Text)  # JSON list
    signals: Mapped[str | None] = mapped_column(Text)  # JSON list, redacted
    approval_id: Mapped[int | None]
    outcome: Mapped[str | None]
    guard: Mapped[str | None]  # control that produced the decision


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    tool_name: Mapped[str]
    arguments: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(default="PENDING")
    created_at: Mapped[str] = mapped_column(default=now)
    reviewed_at: Mapped[str | None]
    reviewer_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[str | None]
    arguments_hash: Mapped[str | None]
    risk_score: Mapped[int | None]
    reason: Mapped[str | None]
    correlation_id: Mapped[str | None]
    executed_at: Mapped[str | None]
    result: Mapped[str | None] = mapped_column(Text)
