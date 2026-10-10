from sqlalchemy import Column, Integer, String, DateTime, LargeBinary
from datetime import datetime

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    email = Column(
        String,
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = Column(
        String,
        nullable=False
    )

    session_token = Column(
        String,
        unique=True,
        nullable=True,
        index=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


class Document(Base):
    __tablename__ = "documents"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=True,
        index=True
    )

    name = Column(
        String,
        nullable=False
    )

    file_path = Column(
        String,
        nullable=True
    )

    file_content = Column(
        LargeBinary,
        nullable=True
    )

    file_name = Column(
        String,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )

    status = Column(
        String,
        default="active"
    )

    action = Column(
        String,
        default="archive"
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    document_id = Column(
        Integer,
        nullable=False
    )

    document_name = Column(
        String,
        nullable=False
    )

    action = Column(
        String,
        nullable=False
    )

    result = Column(
        String,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


# =========================================================
# ТОКЕНЫ ВОССТАНОВЛЕНИЯ ПАРОЛЯ
# =========================================================

class PasswordResetToken(Base):

    __tablename__ = "password_reset_tokens"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    token_hash = Column(
        String,
        unique=True,
        nullable=False,
        index=True
    )

    expires_at = Column(
        DateTime,
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    used_at = Column(
        DateTime,
        nullable=True
    )


class OrganizationProfile(Base):
    __tablename__ = "organization_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, unique=True, nullable=False, index=True)
    organization_name = Column(String, nullable=False, default="")
    subdivision = Column(String, nullable=False, default="")
    responsible_person = Column(String, nullable=False, default="")
    retention_policy = Column(String, nullable=False, default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
