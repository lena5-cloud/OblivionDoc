from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


COMMON_WEAK_PASSWORDS = {
    "12345678", "123456789", "1234567890", "11111111", "00000000",
    "qwerty", "qwerty123", "qwerty12345", "password", "password1",
    "password123", "admin", "admin123", "welcome", "welcome123",
    "letmein", "letmein123", "iloveyou", "abc12345", "test1234",
    "user1234", "пароль", "пароль123", "йцукен", "йцукен123",
}


def validate_password_strength(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Введите пароль.")

    if len(value) < 8:
        raise ValueError("Пароль должен содержать не менее 8 символов.")

    if len(value) > 100:
        raise ValueError("Пароль не должен быть длиннее 100 символов.")

    if any(char.isspace() for char in value):
        raise ValueError("Пароль не должен содержать пробелы.")

    compact = "".join(char for char in value.casefold() if char.isalnum())
    leet_value = value.casefold().translate(
        str.maketrans({"@": "a", "$": "s", "0": "o", "1": "i",
                       "3": "e", "4": "a", "5": "s", "7": "t"})
    )
    leet_compact = "".join(char for char in leet_value if char.isalnum())

    if compact in COMMON_WEAK_PASSWORDS or leet_compact in COMMON_WEAK_PASSWORDS:
        raise ValueError("Этот пароль слишком распространённый. Выберите другой.")

    if not any(char.isupper() for char in value):
        raise ValueError("Добавьте в пароль хотя бы одну заглавную букву.")

    if not any(char.islower() for char in value):
        raise ValueError("Добавьте в пароль хотя бы одну строчную букву.")

    if not any(char.isdigit() for char in value):
        raise ValueError("Добавьте в пароль хотя бы одну цифру.")

    if not any(not char.isalnum() and not char.isspace() for char in value):
        raise ValueError("Добавьте в пароль хотя бы один специальный символ.")

    return value

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

    @field_validator("password", mode="before")
    @classmethod
    def password_policy(cls, value: str) -> str:
        return validate_password_strength(value)


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

    @field_validator("password", mode="before")
    @classmethod
    def password_policy(cls, value: str) -> str:
        return validate_password_strength(value)

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
