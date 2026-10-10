from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal


class UserRegister(BaseModel):

    email: str = Field(
        min_length=5,
        max_length=100
    )

    password: str = Field(
        min_length=6,
        max_length=100
    )


class UserLogin(BaseModel):

    email: str

    password: str


class UserResponse(BaseModel):

    id: int

    email: str

    created_at: datetime

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):

    message: str

    session_token: str

    user: UserResponse


class DocumentCreate(BaseModel):

    name: str

    expires_at: datetime

    action: Literal[
        "archive",
        "delete"
    ] = "archive"


class DocumentUpdate(BaseModel):

    name: str

    expires_at: datetime

    action: Literal[
        "archive",
        "delete"
    ]


class DocumentResponse(BaseModel):

    id: int

    user_id: int | None

    name: str

    file_path: str | None

    created_at: datetime

    expires_at: datetime

    status: str

    action: str

    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):

    id: int

    document_id: int

    document_name: str

    action: str

    result: str

    created_at: datetime

    class Config:
        from_attributes = True


# =========================================================
# ВОССТАНОВЛЕНИЕ ПАРОЛЯ
# =========================================================

class PasswordResetRequest(BaseModel):

    email: str


class PasswordResetConfirm(BaseModel):

    token: str

    password: str = Field(
        min_length=6,
        max_length=100
    )


class OrganizationSettingsData(BaseModel):
    organization_name: str = Field(default="", max_length=200)
    subdivision: str = Field(default="", max_length=200)
    responsible_person: str = Field(default="", max_length=200)
    retention_policy: str = Field(default="", max_length=1000)
