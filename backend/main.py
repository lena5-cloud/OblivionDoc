from fastapi import (

    FastAPI,

    Depends,

    HTTPException,

    UploadFile,

    File,

    Form

)

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import FileResponse, Response

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sqlalchemy.orm import Session

from sqlalchemy import text

from datetime import datetime, timezone, timedelta

import os

import shutil

import secrets

import hashlib

import base64

import uuid
import json
import mimetypes
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

from .database import (

    Base,

    engine,

    get_db,

    SessionLocal

)

from .models import (

    User,

    Document,

    AuditLog,

    PasswordResetToken,
    OrganizationProfile,
    UserProfile

)

from .schemas import (

    UserRegister,

    UserLogin,

    UserResponse,

    LoginResponse,

    DocumentCreate,

    DocumentUpdate,

    DocumentResponse,

    AuditLogResponse,

    PasswordResetRequest,

    PasswordResetConfirm,
    OrganizationSettingsData,
    UserProfileData

)

from .xlsx_export import build_xlsx

# FASTAPI

app = FastAPI(title="OblivionDoc API", version="1.0.0")

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# CORS

app.add_middleware(

    CORSMiddleware,

    allow_origins=[

        "http://127.0.0.1:5500",

        "http://localhost:5500",

        "https://obliviondoc-site.onrender.com"

    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)

# ПУТИ К ПАПКАМ

BASE_DIR = Path(__file__).resolve().parent.parent

UPLOADS_DIR = BASE_DIR / "uploads"

ARCHIVE_DIR = BASE_DIR / "archive"

UPLOADS_DIR.mkdir(exist_ok=True)

ARCHIVE_DIR.mkdir(exist_ok=True)

# НАСТРОЙКИ ФАЙЛОВ

MAX_FILE_SIZE = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {

    ".pdf",

    ".doc",

    ".docx",

    ".txt",

    ".png",

    ".jpg",

    ".jpeg"

}

# НАСТРОЙКИ ВОССТАНОВЛЕНИЯ ПАРОЛЯ

RESET_TOKEN_LIFETIME_MINUTES = 60

RESEND_API_KEY = os.getenv(

    "RESEND_API_KEY",

    ""

)

RESEND_FROM = os.getenv("RESEND_FROM", "").strip()

RUSENDER_API_KEY = os.getenv("RUSENDER_API_KEY", "").strip()
RUSENDER_KEY_ID = os.getenv("RUSENDER_KEY_ID", "").strip()
RUSENDER_FROM = (
    os.getenv("RUSENDER_FROM", "").strip()
    or os.getenv("OBLIVION_SMTP_FROM", "").strip()
)
RUSENDER_API_URL = "https://api.rusender.ru/api/v1/external-mails/send"

RESEND_API_URL = "https://api.resend.com/emails"

IS_RENDER_ENV = bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))
if IS_RENDER_ENV:
    FRONTEND_URL = os.getenv(
        "OBLIVION_FRONTEND_URL",
        "https://obliviondoc-site.onrender.com"
    ).strip().rstrip("/")
else:
    FRONTEND_URL = os.getenv(
        "OBLIVION_TEST_FRONTEND_URL",
        "http://127.0.0.1:8000"
    ).strip().rstrip("/")

# СОЗДАНИЕ ТАБЛИЦ

Base.metadata.create_all(bind=engine)

# МИГРАЦИЯ БАЗЫ

def migrate_database():

    from sqlalchemy import inspect

    inspector = inspect(engine)
    if "documents" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("documents")}

    with engine.begin() as connection:
        if "user_id" not in columns:
            connection.execute(
                text("ALTER TABLE documents ADD COLUMN user_id INTEGER")
            )
            print("База данных обновлена: добавлен user_id.")

        if "file_content" not in columns:
            statement = (
                "ALTER TABLE documents ADD COLUMN file_content BYTEA"
                if engine.dialect.name == "postgresql"
                else "ALTER TABLE documents ADD COLUMN file_content BLOB"
            )
            connection.execute(text(statement))
            print("База данных обновлена: добавлено хранилище файлов.")

        if "file_name" not in columns:
            connection.execute(
                text("ALTER TABLE documents ADD COLUMN file_name VARCHAR")
            )
            print("База данных обновлена: добавлено имя файла.")

        document_columns = {
            "category": "VARCHAR(80) NOT NULL DEFAULT 'other'",
            "department": "VARCHAR(200) NOT NULL DEFAULT ''",
            "document_number": "VARCHAR(120) NOT NULL DEFAULT ''",
            "counterparty": "VARCHAR(200) NOT NULL DEFAULT ''",
            "responsible_person": "VARCHAR(200) NOT NULL DEFAULT ''",
            "notes": "TEXT NOT NULL DEFAULT ''",
        }
        for column_name, column_type in document_columns.items():
            if column_name not in columns:
                connection.execute(text(
                    f"ALTER TABLE documents ADD COLUMN {column_name} {column_type}"
                ))
                print(f"База данных обновлена: добавлено поле {column_name}.")

        table_names = set(inspector.get_table_names())
        if "organization_profiles" in table_names:
            organization_columns = {
                column["name"]
                for column in inspector.get_columns("organization_profiles")
            }
            for column_name, column_type in {
                "organization_type": "VARCHAR(80) NOT NULL DEFAULT 'company'",
                "industry": "VARCHAR(80) NOT NULL DEFAULT 'other'",
            }.items():
                if column_name not in organization_columns:
                    connection.execute(text(
                        f"ALTER TABLE organization_profiles ADD COLUMN {column_name} {column_type}"
                    ))
                    print(f"База данных обновлена: добавлено поле организации {column_name}.")

        user_count = connection.execute(
            text("SELECT COUNT(*) FROM users")
        ).scalar_one()
        if user_count == 1:
            connection.execute(
                text(
                    "UPDATE documents SET user_id = (SELECT id FROM users LIMIT 1) "
                    "WHERE user_id IS NULL"
                )
            )

        stored_tokens = connection.execute(
            text("SELECT id, session_token FROM users WHERE session_token IS NOT NULL")
        ).all()
        for user_id, stored_token in stored_tokens:
            token_value = str(stored_token)
            already_hashed = (
                len(token_value) == 64
                and all(char in "0123456789abcdefABCDEF" for char in token_value)
            )
            if not already_hashed:
                connection.execute(
                    text("UPDATE users SET session_token = :token WHERE id = :user_id"),
                    {
                        "token": hashlib.sha256(token_value.encode("utf-8")).hexdigest(),
                        "user_id": user_id,
                    },
                )

migrate_database()

# РАБОТА С ДАТОЙ

def normalize_datetime(

    value: datetime

) -> datetime:

    """

    Приводит дату к единому виду.

    Если браузер отправил дату с timezone,

    переводим её в UTC и убираем timezone.

    SQLite после этого получает обычную

    дату без timezone.

    """

    if value.tzinfo is not None:

        value = value.astimezone(

            timezone.utc

        )

        value = value.replace(

            tzinfo=None

        )

    return value

def utc_now() -> datetime:

    """

    Текущее время UTC без timezone.

    """

    return datetime.now(

        timezone.utc

    ).replace(

        tzinfo=None

    )

# ХЕШИРОВАНИЕ ПАРОЛЯ

def hash_password(

    password: str

) -> str:

    salt = secrets.token_bytes(16)

    password_hash = hashlib.scrypt(

        password.encode("utf-8"),

        salt=salt,

        n=16384,

        r=8,

        p=1,

        dklen=64

    )

    salt_text = base64.b64encode(

        salt

    ).decode("utf-8")

    hash_text = base64.b64encode(

        password_hash

    ).decode("utf-8")

    return (

        f"scrypt$16384$8$1$"

        f"{salt_text}${hash_text}"

    )

def verify_password(

    password: str,

    stored_hash: str

) -> bool:

    try:

        parts = stored_hash.split("$")

        if len(parts) != 6:

            return False

        algorithm = parts[0]

        n = int(parts[1])

        r = int(parts[2])

        p = int(parts[3])

        salt = base64.b64decode(

            parts[4]

        )

        original_hash = base64.b64decode(

            parts[5]

        )

        if algorithm != "scrypt" or (n, r, p) != (16384, 8, 1):
            return False
        if len(salt) != 16 or len(original_hash) != 64:
            return False

        new_hash = hashlib.scrypt(

            password.encode("utf-8"),

            salt=salt,

            n=n,

            r=r,

            p=p,

            dklen=len(original_hash)

        )

        return secrets.compare_digest(

            new_hash,

            original_hash

        )

    except Exception:

        return False

# ВОССТАНОВЛЕНИЕ ПАРОЛЯ

def _post_email_json(provider: str, url: str, payload: dict, headers: dict) -> bool:
    """Send JSON email request and log provider responses without exposing API keys."""
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={**headers, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
        try:
            result = json.loads(body) if body else {}
        except json.JSONDecodeError:
            result = {}
        message_id = result.get("id") or result.get("uuid") or "не указан"
        print("{}: письмо принято сервисом; ID: {}".format(provider, message_id))
        return True
    except HTTPError as error:
        try:
            body = error.read().decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
                detail = data.get("message") or data.get("detail") or data.get("error") or "без описания"
            except json.JSONDecodeError:
                detail = body[:300] or "без описания"
        except Exception:
            detail = "не удалось прочитать ответ сервиса"
        print("{}: HTTP {}: {}".format(provider, error.code, str(detail)[:300]))
        return False
    except URLError as error:
        print("{}: ошибка соединения: {}".format(provider, error.reason))
        return False
    except Exception as error:
        print("{}: ошибка отправки: {}: {}".format(provider, type(error).__name__, error))
        return False


def send_password_reset_email(

    email: str,

    reset_link: str

):

    """Отправляет письмо восстановления через Resend HTTPS API."""

    subject = (
        "OblivionDoc — восстановление пароля "
        f"({datetime.now().strftime('%d.%m.%Y %H:%M')})"
    )

    html_text = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Восстановление пароля OblivionDoc</title>
</head>
<body style="
    margin: 0;
    padding: 0;
    background-color: #f4f6f8;
    font-family: Arial, Helvetica, sans-serif;
    color: #111111;
">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f4f6f8;padding:32px 0;">
        <tr><td align="center">
            <table width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:600px;background-color:#ffffff;border-radius:12px;">
                <tr><td style="padding:34px 30px;">
                    <h2 style="margin:0 0 24px 0;font-size:22px;line-height:1.3;color:#111111;">
                        Восстановление пароля OblivionDoc
                    </h2>
                    <p style="margin:0 0 18px 0;font-size:16px;line-height:1.6;color:#111111;">
                        Здравствуйте!
                    </p>
                    <p style="margin:0 0 18px 0;font-size:16px;line-height:1.6;color:#111111;">
                        Вы запросили восстановление пароля для OblivionDoc.
                    </p>
                    <p style="margin:0 0 24px 0;font-size:16px;line-height:1.6;color:#111111;">
                        Для восстановления пароля нажмите на кнопку ниже:
                    </p>
                    <table width="100%" cellpadding="0" cellspacing="0" border="0">
                        <tr><td align="center" style="padding:4px 0 28px 0;">
                            <a href="{reset_link}" target="_blank" style="display:inline-block;padding:14px 24px;background-color:#222222;color:#ffffff;text-decoration:none;border-radius:8px;font-size:16px;font-weight:bold;line-height:1.2;">
                                Восстановить пароль
                            </a>
                        </td></tr>
                    </table>
                    <p style="margin:0 0 18px 0;font-size:14px;line-height:1.6;color:#555555;">
                        Ссылка действует <strong>{RESET_TOKEN_LIFETIME_MINUTES} минут</strong>.
                    </p>
                    <p style="margin:0 0 24px 0;font-size:14px;line-height:1.6;color:#555555;">
                        Если вы не запрашивали восстановление пароля, просто проигнорируйте это письмо.
                    </p>
                    <p style="margin:0;font-size:14px;line-height:1.6;color:#111111;">
                        С уважением,<br><strong>OblivionDoc</strong>
                    </p>
                </td></tr>
            </table>
        </td></tr>
    </table>
</body>
</html>
"""

    # RuSender: SMTP credentials are not used here; Render Free restricts SMTP ports.
    if RUSENDER_API_KEY and RUSENDER_FROM:
        payload = {
            "idempotencyKey": "obliviondoc-reset-" + secrets.token_urlsafe(18),
            "mail": {
                "to": {"email": email},
                "from": {"email": RUSENDER_FROM, "name": "OblivionDoc"},
                "subject": subject,
                "html": html_text,
            },
        }
        if RUSENDER_API_KEY.startswith("rs_ck_v1_"):
            if RUSENDER_KEY_ID:
                sent = _post_email_json(
                    "RuSender",
                    RUSENDER_API_URL + "/" + quote(RUSENDER_KEY_ID, safe=""),
                    payload,
                    {"Authorization": "Bearer " + RUSENDER_API_KEY},
                )
                if sent:
                    return True
            else:
                print("RuSender: токен rs_ck_v1_ требует RUSENDER_KEY_ID в Environment Render.")
        else:
            sent = _post_email_json(
                "RuSender",
                RUSENDER_API_URL,
                payload,
                {"X-Api-Key": RUSENDER_API_KEY},
            )
            if sent:
                return True
    elif RUSENDER_API_KEY:
        print("RuSender: RUSENDER_API_KEY есть, но не задан адрес OBLIVION_SMTP_FROM/RUSENDER_FROM.")

    # Resend is an optional fallback only if a sender on a verified domain is configured.
    if RESEND_API_KEY and RESEND_FROM:
        resend_payload = {
            "from": RESEND_FROM,
            "to": [email],
            "subject": subject,
            "html": html_text,
        }
        if _post_email_json(
            "Resend",
            RESEND_API_URL,
            resend_payload,
            {"Authorization": "Bearer " + RESEND_API_KEY},
        ):
            return True
    elif RESEND_API_KEY:
        print("Resend: RESEND_FROM не задан. Для реальной отправки нужен подтверждённый домен и адрес отправителя.")

    print("Ссылка восстановления не отправлена; проверьте сообщения выше в Render Logs.")
    return False


def create_password_reset_token(

    user: User,

    db: Session

):

    # Удаляем старые токены пользователя

    old_tokens = (

        db.query(PasswordResetToken)

        .filter(

            PasswordResetToken.user_id

            == user.id

        )

        .all()

    )

    for old_token in old_tokens:

        db.delete(old_token)

    db.commit()

    # Создаём новый случайный токен

    raw_token = secrets.token_urlsafe(24)

    token_hash = hashlib.sha256(

        raw_token.encode("utf-8")

    ).hexdigest()

    expires_at = (

        utc_now()

        + timedelta(

            minutes=RESET_TOKEN_LIFETIME_MINUTES

        )

    )

    reset_token = PasswordResetToken(

        user_id=user.id,

        token_hash=token_hash,

        expires_at=expires_at

    )

    db.add(reset_token)

    db.commit()

    reset_link = (

        f"{FRONTEND_URL}"

        f"/?reset_token={raw_token}"

    )

    return reset_link

# АВТОРИЗАЦИЯ

security = HTTPBearer()

def get_current_user(

    credentials: HTTPAuthorizationCredentials = Depends(

        security

    ),

    db: Session = Depends(get_db)

):

    token_hash = hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest()
    user = db.query(User).filter(User.session_token == token_hash).first()

    if not user:

        raise HTTPException(

            status_code=401,

            detail="Недействительная сессия."

        )

    return user

# ГЛАВНАЯ

@app.get("/settings/organization")
def get_organization_settings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    profile = (
        db.query(OrganizationProfile)
        .filter(OrganizationProfile.user_id == current_user.id)
        .first()
    )
    if not profile:
        return {
            "organization_name": "",
            "organization_type": "company",
            "industry": "other",
            "subdivision": "",
            "responsible_person": "",
            "retention_policy": ""
        }
    return {
        "organization_name": profile.organization_name,
        "organization_type": profile.organization_type or "company",
        "industry": profile.industry or "other",
        "subdivision": profile.subdivision,
        "responsible_person": profile.responsible_person,
        "retention_policy": profile.retention_policy
    }

@app.put("/settings/organization")
def save_organization_settings(
    settings: OrganizationSettingsData,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    organization_name = settings.organization_name.strip()
    organization_type = settings.organization_type.strip()
    industry = settings.industry.strip()
    subdivision = settings.subdivision.strip()
    responsible_person = settings.responsible_person.strip()
    retention_policy = settings.retention_policy.strip()
    allowed_organization_types = {"company", "public", "nonprofit", "individual", "other"}
    allowed_industries = {
        "construction", "accounting_finance", "legal_services", "logistics",
        "housing_utilities", "education", "manufacturing", "healthcare",
        "retail_services", "agriculture", "it_telecom", "professional_services",
        "public_services", "other"
    }
    if not organization_name:
        raise HTTPException(
            status_code=422,
            detail="Укажите название организации.",
        )
    if organization_type not in allowed_organization_types:
        raise HTTPException(status_code=422, detail="Выберите тип организации из списка.")
    if industry not in allowed_industries:
        raise HTTPException(status_code=422, detail="Выберите отрасль из списка.")

    profile = (
        db.query(OrganizationProfile)
        .filter(OrganizationProfile.user_id == current_user.id)
        .first()
    )
    if not profile:
        profile = OrganizationProfile(user_id=current_user.id)
        db.add(profile)

    profile.organization_name = organization_name
    profile.organization_type = organization_type
    profile.industry = industry
    profile.subdivision = subdivision
    profile.responsible_person = responsible_person
    profile.retention_policy = retention_policy
    db.commit()
    db.refresh(profile)

    return {
        "message": "Настройки организации сохранены.",
        "organization_name": profile.organization_name,
        "organization_type": profile.organization_type or "company",
        "industry": profile.industry or "other",
        "subdivision": profile.subdivision,
        "responsible_person": profile.responsible_person,
        "retention_policy": profile.retention_policy
    }


@app.get("/profile")
def get_user_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    profile = (
        db.query(UserProfile)
        .filter(UserProfile.user_id == current_user.id)
        .first()
    )
    if not profile:
        return {"first_name": "", "last_name": ""}
    return {
        "first_name": profile.first_name,
        "last_name": profile.last_name
    }

@app.put("/profile")
def save_user_profile(
    data: UserProfileData,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    first_name = data.first_name.strip()
    last_name = data.last_name.strip()
    profile = (
        db.query(UserProfile)
        .filter(UserProfile.user_id == current_user.id)
        .first()
    )
    if not profile:
        profile = UserProfile(user_id=current_user.id)
        db.add(profile)
    profile.first_name = first_name
    profile.last_name = last_name
    db.commit()
    db.refresh(profile)
    return {
        "message": "Профиль сохранён.",
        "first_name": profile.first_name,
        "last_name": profile.last_name
    }

@app.get("/")
def root():
    frontend_file = BASE_DIR / "frontend" / "index.html"
    if frontend_file.exists():
        return FileResponse(frontend_file, media_type="text/html")
    return {"message": "OblivionDoc API работает"}

@app.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception as error:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="API запущен, но база данных недоступна.",
        ) from error
    return {"status": "ok", "database": "connected"}

# РЕГИСТРАЦИЯ

@app.post("/auth/register", response_model=LoginResponse)
def register(
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    email = user_data.email.strip().lower()
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Пользователь с таким email уже существует."
        )

    session_token = secrets.token_urlsafe(32)
    user = User(
        email=email,
        password_hash=hash_password(user_data.password),
        session_token=hashlib.sha256(session_token.encode("utf-8")).hexdigest(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return LoginResponse(
        message="Аккаунт создан. Добро пожаловать в OblivionDoc!",
        session_token=session_token,
        user=user
    )

# ВХОД

@app.post(

    "/auth/login",

    response_model=LoginResponse

)

def login(

    login_data: UserLogin,

    db: Session = Depends(get_db)

):

    user = (

        db.query(User)

        .filter(

            User.email == login_data.email.strip().lower()

        )

        .first()

    )

    if not user:

        raise HTTPException(

            status_code=401,

            detail="Неверный email или пароль."

        )

    if not verify_password(

        login_data.password,

        user.password_hash

    ):

        raise HTTPException(

            status_code=401,

            detail="Неверный email или пароль."

        )

    session_token = secrets.token_urlsafe(32)

    user.session_token = hashlib.sha256(session_token.encode("utf-8")).hexdigest()

    db.commit()

    db.refresh(user)

    return LoginResponse(

        message="Вход выполнен успешно.",

        session_token=session_token,

        user=user

    )

# ЗАПРОС ВОССТАНОВЛЕНИЯ ПАРОЛЯ

@app.post(

    "/auth/forgot-password"

)

def forgot_password(

    request: PasswordResetRequest,

    db: Session = Depends(get_db)

):

    user = (

        db.query(User)

        .filter(

            User.email == request.email.strip().lower()

        )

        .first()

    )

    # Не сообщаем, существует ли аккаунт.

    # Это безопаснее с точки зрения защиты

    # информации о пользователях.

    if not user:

        return {

            "message": (

                "Если аккаунт с таким email "

                "существует, ссылка для "

                "восстановления отправлена."

            )

        }

    reset_link = create_password_reset_token(

        user,

        db

    )

    # Отправляем письмо напрямую через HTTPS API Resend.
    # Так мы точно получаем ответ сервиса и можем увидеть
    # причину ошибки в логах Render.
    email_sent = send_password_reset_email(
        user.email,
        reset_link
    )

    if not email_sent:
        raise HTTPException(
            status_code=502,
            detail=(
                "Не удалось отправить письмо "
                "для восстановления пароля."
            )
        )

    return {
        "message": (
            "Если аккаунт с таким email "
            "существует, ссылка для "
            "восстановления отправлена."
        )
    }

# УСТАНОВКА НОВОГО ПАРОЛЯ

@app.post(

    "/auth/reset-password"

)

def reset_password(

    reset_data: PasswordResetConfirm,

    db: Session = Depends(get_db)

):

    token_hash = hashlib.sha256(

        reset_data.token.encode("utf-8")

    ).hexdigest()

    reset_token = (

        db.query(PasswordResetToken)

        .filter(

            PasswordResetToken.token_hash

            == token_hash

        )

        .first()

    )

    if not reset_token:

        raise HTTPException(

            status_code=400,

            detail=(

                "Недействительная или "

                "устаревшая ссылка."

            )

        )

    if reset_token.used_at is not None:

        raise HTTPException(

            status_code=400,

            detail=(

                "Эта ссылка уже была использована. "

                "Запросите новую."

            )

        )

    if reset_token.expires_at <= utc_now():

        db.delete(reset_token)

        db.commit()

        raise HTTPException(

            status_code=400,

            detail=(

                "Срок действия ссылки истёк. "

                "Запросите новую."

            )

        )

    user = (

        db.query(User)

        .filter(

            User.id == reset_token.user_id

        )

        .first()

    )

    if not user:

        raise HTTPException(

            status_code=400,

            detail="Пользователь не найден."

        )

    user.password_hash = hash_password(

        reset_data.password

    )

    user.session_token = None

    reset_token.used_at = utc_now()

    db.commit()

    return {

        "message": (

            "Пароль успешно изменён. "

            "Теперь можно войти."

        )

    }

# ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ

@app.get(

    "/auth/me",

    response_model=UserResponse

)

def get_me(

    current_user: User = Depends(

        get_current_user

    )

):

    return current_user

# ВЫХОД

@app.post("/auth/logout")

def logout(

    current_user: User = Depends(

        get_current_user

    ),

    db: Session = Depends(get_db)

):

    current_user.session_token = None

    db.commit()

    return {

        "message": "Выход выполнен успешно."

    }

# ПОЛУЧИТЬ ДОКУМЕНТЫ

@app.get(

    "/documents",

    response_model=list[DocumentResponse]

)

def get_documents(

    current_user: User = Depends(

        get_current_user

    ),

    db: Session = Depends(get_db)

):

    documents = (

        db.query(Document)

        .filter(

            Document.user_id

            == current_user.id

        )

        .order_by(

            Document.id.desc()

        )

        .all()

    )

    return documents

# СОЗДАНИЕ ДОКУМЕНТА

@app.post("/documents", response_model=DocumentResponse)
def create_document_without_file(
    document_data: DocumentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    raise HTTPException(
        status_code=400,
        detail="При создании документа необходимо прикрепить файл.",
    )

# СОЗДАНИЕ ДОКУМЕНТА С ФАЙЛОМ

@app.post(

    "/documents/upload",

    response_model=DocumentResponse

)

async def create_document_upload(

    name: str = Form(...),

    expires_at: datetime = Form(...),

    action: str = Form("archive"),
    category: str = Form("other"),
    department: str = Form(""),
    document_number: str = Form(""),
    counterparty: str = Form(""),
    responsible_person: str = Form(""),
    notes: str = Form(""),

    file: UploadFile = File(...),

    current_user: User = Depends(

        get_current_user

    ),

    db: Session = Depends(get_db)

):

    if action not in {

        "archive",

        "delete"

    }:

        raise HTTPException(

            status_code=400,

            detail="Недопустимое действие."

        )

    allowed_categories = {
        "contracts", "finance", "hr", "legal", "project_technical",
        "construction", "logistics", "medical", "education", "procurement",
        "management", "housing_utilities", "correspondence", "other"
    }
    if category not in allowed_categories:
        raise HTTPException(status_code=400, detail="Выберите категорию документа из списка.")
    if file is None or not file.filename:
        raise HTTPException(
            status_code=400,
            detail="При создании документа необходимо прикрепить файл."
        )

    expires_at = normalize_datetime(expires_at)

    file_path = None
    file_content = bytearray()
    original_name = file.filename or ""

    if file:

        extension = Path(

            original_name

        ).suffix.lower()

        if extension not in ALLOWED_EXTENSIONS:

            raise HTTPException(

                status_code=400,

                detail=(

                    "Недопустимый тип файла. "

                    "Разрешены PDF, DOC, DOCX, "

                    "TXT, PNG, JPG и JPEG."

                )

            )

        unique_name = (

            f"{uuid.uuid4().hex}"

            f"{extension}"

        )

        save_path = (

            UPLOADS_DIR /

            unique_name

        )

        total_size = 0

        try:

            with open(

                save_path,

                "wb"

            ) as buffer:

                while True:

                    chunk = await file.read(

                        1024 * 1024

                    )

                    if not chunk:

                        break

                    total_size += len(chunk)
                    file_content.extend(chunk)

                    if total_size > MAX_FILE_SIZE:

                        raise HTTPException(

                            status_code=400,

                            detail=(

                                "Размер файла "

                                "не должен превышать 10 МБ."

                            )

                        )

                    buffer.write(chunk)

        except HTTPException:

            if save_path.exists():

                save_path.unlink()

            raise

        except Exception:

            if save_path.exists():

                save_path.unlink()

            raise HTTPException(

                status_code=500,

                detail="Ошибка сохранения файла."

            )

        file_path = str(save_path)

    document = Document(

        user_id=current_user.id,

        name=name.strip(),
        file_path=file_path,
        file_content=bytes(file_content),
        file_name=original_name,
        category=category,
        department=department.strip(),
        document_number=document_number.strip(),
        counterparty=counterparty.strip(),
        responsible_person=responsible_person.strip(),
        notes=notes.strip(),
        expires_at=expires_at,
        status="active",
        action=action

    )

    try:
        db.add(document)
        db.flush()
        db.add(AuditLog(
            document_id=document.id,
            document_name=document.name,
            action="create",
            result="success",
        ))
        db.commit()
        db.refresh(document)
    except Exception as error:
        db.rollback()
        if file_path and Path(file_path).exists():
            try:
                Path(file_path).unlink()
            except OSError:
                pass
        raise HTTPException(
            status_code=500,
            detail="Не удалось сохранить документ в базе данных. Попробуйте ещё раз.",
        ) from error

    return document

# ИЗМЕНЕНИЕ ДОКУМЕНТА

@app.put(

    "/documents/{document_id}",

    response_model=DocumentResponse

)

def update_document(

    document_id: int,

    document_data: DocumentUpdate,

    current_user: User = Depends(

        get_current_user

    ),

    db: Session = Depends(get_db)

):

    document = (

        db.query(Document)

        .filter(

            Document.id == document_id,

            Document.user_id == current_user.id

        )

        .first()

    )

    if not document:

        raise HTTPException(

            status_code=404,

            detail="Документ не найден."

        )

    new_name = document_data.name.strip()
    new_expires_at = normalize_datetime(document_data.expires_at)
    new_action = document_data.action
    new_category = document_data.category
    allowed_categories = {
        "contracts", "finance", "hr", "legal", "project_technical",
        "construction", "logistics", "medical", "education", "procurement",
        "management", "housing_utilities", "correspondence", "other"
    }
    if new_category not in allowed_categories:
        raise HTTPException(status_code=422, detail="Выберите категорию документа из списка.")
    new_metadata = {
        "department": document_data.department.strip(),
        "document_number": document_data.document_number.strip(),
        "counterparty": document_data.counterparty.strip(),
        "responsible_person": document_data.responsible_person.strip(),
        "notes": document_data.notes.strip(),
    }

    changed = (
        document.name != new_name
        or document.expires_at != new_expires_at
        or document.action != new_action
        or (document.category or "other") != new_category
        or any(getattr(document, key, "") != value for key, value in new_metadata.items())
    )

    if not changed:
        return document

    document.name = new_name
    document.expires_at = new_expires_at
    document.action = new_action
    document.category = new_category
    for key, value in new_metadata.items():
        setattr(document, key, value)

    if document.expires_at > utc_now():
        document.status = "active"
    elif document.action == "archive":
        document.status = "archived"
    elif document.action == "delete":
        document.status = "deleted"

    audit = AuditLog(
        document_id=document.id,
        document_name=document.name,
        action="update",
        result="success"
    )
    db.add(audit)
    db.commit()
    db.refresh(document)
    return document

# УДАЛЕНИЕ ДОКУМЕНТА

@app.delete(

    "/documents/{document_id}"

)
def delete_document(

    document_id: int,

    current_user: User = Depends(
        get_current_user
    ),

    db: Session = Depends(get_db)

):

    document = (
        db.query(Document)
        .filter(
            Document.id == document_id,
            Document.user_id == current_user.id
        )
        .first()
    )

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Документ не найден."
        )

    if document.file_path:
        file_path = Path(document.file_path)

        if file_path.exists():
            try:
                file_path.unlink()
            except Exception as error:
                raise HTTPException(
                    status_code=500,
                    detail="Не удалось удалить файл документа."
                ) from error

    # Сохраняем запись документа в БД со статусом deleted.
    # Так история действий остаётся доступной в аудите.
    document.file_path = None
    document.file_content = None
    document.file_name = None
    document.status = "deleted"

    audit = AuditLog(
        document_id=document.id,
        document_name=document.name,
        action="delete",
        result="success"
    )

    db.add(audit)
    db.commit()

    return {
        "message": "Документ удалён."
    }

# СКАЧИВАНИЕ

@app.get(

    "/documents/{document_id}/download"

)

def download_document(

    document_id: int,

    current_user: User = Depends(

        get_current_user

    ),

    db: Session = Depends(get_db)

):

    document = (

        db.query(Document)

        .filter(

            Document.id == document_id,

            Document.user_id == current_user.id

        )

        .first()

    )

    if not document:

        raise HTTPException(

            status_code=404,

            detail="Документ не найден."

        )

    # Сначала пробуем локальный файл. Он ускоряет скачивание, но на хостинге
    # может исчезнуть после перезапуска — в таком случае используется копия в БД.
    if document.file_path:
        file_path = Path(document.file_path)
        if file_path.exists():
            return FileResponse(
                path=file_path,
                filename=document.file_name or document.name,
            )

    if document.file_content:
        filename = document.file_name or document.name
        media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        return Response(
            content=document.file_content,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"
            },
        )

    raise HTTPException(
        status_code=404,
        detail="Файл не найден. Для старой записи файл мог быть удалён при перезапуске хостинга."
    )

# АУДИТ

@app.get(

    "/audit-log",
    response_model=list[AuditLogResponse]

)
def get_audit_log(

    current_user: User = Depends(
        get_current_user
    ),

    db: Session = Depends(get_db)

):

    logs = (
        db.query(AuditLog)
        .join(
            Document,
            AuditLog.document_id == Document.id
        )
        .filter(
            Document.user_id == current_user.id
        )
        .order_by(
            AuditLog.created_at.desc()
        )
        .all()
    )

    return logs


@app.get("/exports/documents.xlsx")
def export_documents_xlsx(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    documents = (
        db.query(Document)
        .filter(Document.user_id == current_user.id)
        .order_by(Document.id.desc())
        .all()
    )
    status_labels = {
        "active": "На хранении",
        "archived": "В архиве",
        "deleted": "Удалён"
    }
    action_labels = {
        "archive": "Архивировать",
        "delete": "Удалить по сроку"
    }
    rows = [["ID", "Название", "Создан", "Срок хранения", "Статус", "Действие по сроку"]]
    for document in documents:
        rows.append([
            document.id,
            document.name,
            document.created_at.strftime("%d.%m.%Y %H:%M") if document.created_at else "",
            document.expires_at.strftime("%d.%m.%Y %H:%M") if document.expires_at else "",
            status_labels.get(document.status, document.status or "—"),
            action_labels.get(document.action, document.action or "—")
        ])
    content = build_xlsx(
        rows,
        sheet_name="Документы",
        max_widths=[10, 52, 22, 22, 18, 28]
    )
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=obliviondoc-documents.xlsx"}
    )

@app.get("/exports/audit.xlsx")
def export_audit_xlsx(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    logs = (
        db.query(AuditLog)
        .join(Document, AuditLog.document_id == Document.id)
        .filter(Document.user_id == current_user.id)
        .order_by(AuditLog.created_at.desc())
        .all()
    )
    action_labels = {
        "create": "Создание документа",
        "update": "Изменение документа",
        "delete": "Удаление документа",
        "archive": "Архивирование",
        "auto_archive": "Автоматическое архивирование",
        "auto_delete": "Автоматическое удаление"
    }
    rows = [["Дата и время", "ID документа", "Документ", "Действие", "Результат"]]
    for log in logs:
        rows.append([
            log.created_at.strftime("%d.%m.%Y %H:%M") if log.created_at else "",
            log.document_id,
            log.document_name,
            action_labels.get(log.action, log.action or "Операция"),
            "Выполнено" if log.result == "success" else (log.result or "—")
        ])
    content = build_xlsx(
        rows,
        sheet_name="Журнал действий",
        max_widths=[22, 14, 48, 34, 22]
    )
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=obliviondoc-audit.xlsx"}
    )

# ОБРАБОТКА ИСТЁКШИХ ДОКУМЕНТОВ

def process_expired_documents():

    db = SessionLocal()

    try:

        now = utc_now()

        documents = (
            db.query(Document)
            .filter(
                Document.status == "active",
                Document.expires_at <= now
            )
            .all()
        )

        for document in documents:

            # АРХИВИРОВАНИЕ
            if document.action == "archive":

                if not document.file_path:
                    document.status = "archived"

                    db.add(AuditLog(
                        document_id=document.id,
                        document_name=document.name,
                        action="archive",
                        result="success"
                    ))
                    continue

                source_path = Path(document.file_path)

                if not source_path.exists():
                    if document.file_content:
                        document.status = "archived"
                        db.add(AuditLog(
                            document_id=document.id,
                            document_name=document.name,
                            action="archive",
                            result="success_database_copy"
                        ))
                    else:
                        db.add(AuditLog(
                            document_id=document.id,
                            document_name=document.name,
                            action="archive",
                            result="error_file_not_found"
                        ))
                    continue

                archive_name = (
                    f"{uuid.uuid4().hex}"
                    f"{source_path.suffix}"
                )

                archive_path = (
                    ARCHIVE_DIR / archive_name
                )

                try:
                    shutil.move(
                        str(source_path),
                        str(archive_path)
                    )

                    document.file_path = str(archive_path)
                    document.status = "archived"

                    db.add(AuditLog(
                        document_id=document.id,
                        document_name=document.name,
                        action="archive",
                        result="success"
                    ))

                except Exception as error:
                    print(
                        "Ошибка архивирования:",
                        error
                    )

                    db.add(AuditLog(
                        document_id=document.id,
                        document_name=document.name,
                        action="archive",
                        result="error"
                    ))

            # УДАЛЕНИЕ
            elif document.action == "delete":

                if not document.file_path:
                    document.file_content = None
                    document.file_name = None
                    document.status = "deleted"

                    db.add(AuditLog(
                        document_id=document.id,
                        document_name=document.name,
                        action="delete",
                        result="success"
                    ))
                    continue

                file_path = Path(document.file_path)

                if not file_path.exists():
                    # Файла уже нет — требуемое состояние достигнуто.
                    document.file_path = None
                    document.file_content = None
                    document.file_name = None
                    document.status = "deleted"

                    db.add(AuditLog(
                        document_id=document.id,
                        document_name=document.name,
                        action="delete",
                        result="success_file_already_missing"
                    ))
                    continue

                try:
                    file_path.unlink()

                    document.file_path = None
                    document.file_content = None
                    document.file_name = None
                    document.status = "deleted"

                    db.add(AuditLog(
                        document_id=document.id,
                        document_name=document.name,
                        action="delete",
                        result="success"
                    ))

                except Exception as error:
                    print(
                        "Ошибка удаления файла:",
                        error
                    )

                    # Не ставим deleted, если физическое удаление не удалось.
                    db.add(AuditLog(
                        document_id=document.id,
                        document_name=document.name,
                        action="delete",
                        result="error"
                    ))

        db.commit()

    except Exception as error:
        db.rollback()
        print(
            "Ошибка обработки истёкших документов:",
            error
        )

    finally:
        db.close()

# ПЛАНИРОВЩИК

scheduler = BackgroundScheduler()

@app.on_event("startup")

def start_scheduler():
    if not IS_RENDER_ENV:
        print("Планировщик отключён в локальной тестовой копии.")
        return

    if not scheduler.running:
        scheduler.add_job(
            process_expired_documents,
            "interval",
            minutes=1,
            id="process_expired_documents",
            replace_existing=True,
        )
        scheduler.start()
        print("Планировщик обработки сроков хранения запущен.")
@app.on_event("shutdown")

def stop_scheduler():

    if scheduler.running:

        scheduler.shutdown()

        print(

            "Планировщик остановлен."

        )
