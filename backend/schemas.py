from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal

class UserRegister(BaseModel):

    email: str = Field(
        min_length=5,
        max_length=254,
        pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
    )

    password: str = Field(
        min_length=8,
        max_length=100
    )

class UserLogin(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=100)

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
    name: str = Field(min_length=1, max_length=240)
    expires_at: datetime
    action: Literal["archive", "delete"] = "archive"
    category: str = Field(default="other", max_length=80)
    department: str = Field(default="", max_length=200)
    document_number: str = Field(default="", max_length=120)
    counterparty: str = Field(default="", max_length=200)
    responsible_person: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=2000)

class DocumentUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=240)
    expires_at: datetime
    action: Literal["archive", "delete"]
    category: str = Field(default="other", max_length=80)
    department: str = Field(default="", max_length=200)
    document_number: str = Field(default="", max_length=120)
    counterparty: str = Field(default="", max_length=200)
    responsible_person: str = Field(default="", max_length=200)
    notes: str = Field(default="", max_length=2000)

class DocumentResponse(BaseModel):

    id: int

    user_id: int | None

    name: str
    file_path: str | None
    file_name: str | None = None
    category: str = "other"
    department: str = ""
    document_number: str = ""
    counterparty: str = ""
    responsible_person: str = ""
    notes: str = ""
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

# ВОССТАНОВЛЕНИЕ ПАРОЛЯ

class PasswordResetRequest(BaseModel):

    email: str

class PasswordResetConfirm(BaseModel):

    token: str

    password: str = Field(
        min_length=8,
        max_length=100
    )

class OrganizationSettingsData(BaseModel):
    organization_name: str = Field(default="", max_length=200)
    organization_type: str = Field(default="company", max_length=80)
    industry: str = Field(default="other", max_length=80)
    subdivision: str = Field(default="", max_length=200)
    responsible_person: str = Field(default="", max_length=200)
    retention_policy: str = Field(default="", max_length=1000)


class UserProfileData(BaseModel):
    first_name: str = Field(default="", max_length=100)
    last_name: str = Field(default="", max_length=100)
