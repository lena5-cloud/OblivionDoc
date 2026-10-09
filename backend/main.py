from fastapi import (

    FastAPI,

    Depends,

    HTTPException,

    UploadFile,

    File,

    Form

)

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import FileResponse

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

    PasswordResetToken

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

    PasswordResetConfirm

)

# ============================================================

# FASTAPI

# ============================================================

app = FastAPI(

    title="OblivionDoc API",

    version="1.0.0"

)

# ============================================================

# CORS

# ============================================================

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

# ============================================================

# ПУТИ К ПАПКАМ

# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

UPLOADS_DIR = BASE_DIR / "uploads"

ARCHIVE_DIR = BASE_DIR / "archive"

UPLOADS_DIR.mkdir(exist_ok=True)

ARCHIVE_DIR.mkdir(exist_ok=True)

# ============================================================

# НАСТРОЙКИ ФАЙЛОВ

# ============================================================

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

# ============================================================

# НАСТРОЙКИ ВОССТАНОВЛЕНИЯ ПАРОЛЯ

# ============================================================

RESET_TOKEN_LIFETIME_MINUTES = 60

RESEND_API_KEY = os.getenv(

    "RESEND_API_KEY",

    ""

)

RESEND_FROM = os.getenv(

    "RESEND_FROM",

    "onboarding@resend.dev"

)

RESEND_API_URL = "https://api.resend.com/emails"

FRONTEND_URL = os.getenv(
    "OBLIVION_FRONTEND_URL",
    "https://obliviondoc-site.onrender.com"
)

# ============================================================

# СОЗДАНИЕ ТАБЛИЦ

# ============================================================

Base.metadata.create_all(bind=engine)

# ============================================================

# МИГРАЦИЯ БАЗЫ

# ============================================================

def migrate_database():

    with engine.connect() as connection:

        result = connection.execute(

            text("PRAGMA table_info(documents)")

        )

        columns = [

            row[1]

            for row in result

        ]

        if "user_id" not in columns:

            connection.execute(

                text(

                    "ALTER TABLE documents "

                    "ADD COLUMN user_id INTEGER"

                )

            )

            connection.commit()

            print(

                "База данных обновлена: "

                "добавлен user_id."

            )

migrate_database()

# ============================================================

# РАБОТА С ДАТОЙ

# ============================================================

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

# ============================================================

# ХЕШИРОВАНИЕ ПАРОЛЯ

# ============================================================

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

        if algorithm != "scrypt":

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

# ============================================================

# ВОССТАНОВЛЕНИЕ ПАРОЛЯ

# ============================================================

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

    if not RESEND_API_KEY:
        print("RESEND_API_KEY не настроен.")
        return False

    payload = {
        "from": RESEND_FROM,
        "to": [email],
        "subject": subject,
        "html": html_text,
    }

    request = Request(
        RESEND_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=20) as response:
            response_body = response.read().decode("utf-8")

        result = json.loads(response_body)
        print("Письмо восстановления успешно отправлено через Resend.")
        print("Resend ID:", result.get("id", "не указан"))
        return True

    except HTTPError as error:
        try:
            error_body = error.read().decode("utf-8")
        except Exception:
            error_body = ""
        print("Ошибка Resend API:", error.code, error_body)
        return False

    except URLError as error:
        print("Ошибка подключения к Resend:", error.reason)
        return False

    except Exception as error:
        print("Ошибка отправки email через Resend:", error)
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

# ============================================================

# АВТОРИЗАЦИЯ

# ============================================================

security = HTTPBearer()

def get_current_user(

    credentials: HTTPAuthorizationCredentials = Depends(

        security

    ),

    db: Session = Depends(get_db)

):

    token = credentials.credentials

    user = (

        db.query(User)

        .filter(

            User.session_token == token

        )

        .first()

    )

    if not user:

        raise HTTPException(

            status_code=401,

            detail="Недействительная сессия."

        )

    return user

# ============================================================

# ГЛАВНАЯ

# ============================================================

@app.get("/")
def root():
    frontend_file = BASE_DIR / "frontend" / "index.html"
    if frontend_file.exists():
        return FileResponse(frontend_file, media_type="text/html")
    return {"message": "OblivionDoc API работает"}

# ============================================================

# РЕГИСТРАЦИЯ

# ============================================================

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
        session_token=session_token
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return LoginResponse(
        message="Аккаунт создан. Добро пожаловать в OblivionDoc!",
        session_token=session_token,
        user=user
    )

# ============================================================

# ВХОД

# ============================================================

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

    user.session_token = session_token

    db.commit()

    db.refresh(user)

    return LoginResponse(

        message="Вход выполнен успешно.",

        session_token=session_token,

        user=user

    )

# ============================================================

# ЗАПРОС ВОССТАНОВЛЕНИЯ ПАРОЛЯ

# ============================================================

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

            User.email == request.email

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

# ============================================================

# УСТАНОВКА НОВОГО ПАРОЛЯ

# ============================================================

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

# ============================================================

# ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ

# ============================================================

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

# ============================================================

# ВЫХОД

# ============================================================

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

# ============================================================

# ПОЛУЧИТЬ ДОКУМЕНТЫ

# ============================================================

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

# ============================================================

# СОЗДАНИЕ ДОКУМЕНТА

# ============================================================

@app.post(

    "/documents",

    response_model=DocumentResponse

)

def create_document(

    document_data: DocumentCreate,

    current_user: User = Depends(

        get_current_user

    ),

    db: Session = Depends(get_db)

):

    expires_at = normalize_datetime(

        document_data.expires_at

    )

    document = Document(

        user_id=current_user.id,

        name=document_data.name,

        file_path=None,

        expires_at=expires_at,

        status="active",

        action=document_data.action

    )

    db.add(document)

    db.commit()

    db.refresh(document)

    audit = AuditLog(

        document_id=document.id,

        document_name=document.name,

        action="create",

        result="success"

    )

    db.add(audit)

    db.commit()

    return document

# ============================================================

# СОЗДАНИЕ ДОКУМЕНТА С ФАЙЛОМ

# ============================================================

@app.post(

    "/documents/upload",

    response_model=DocumentResponse

)

async def create_document_upload(

    name: str = Form(...),

    expires_at: datetime = Form(...),

    action: str = Form("archive"),

    file: UploadFile | None = File(None),

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

    expires_at = normalize_datetime(

        expires_at

    )

    file_path = None

    if file:

        original_name = (

            file.filename or ""

        )

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

        name=name,

        file_path=file_path,

        expires_at=expires_at,

        status="active",

        action=action

    )

    db.add(document)

    db.commit()

    db.refresh(document)

    audit = AuditLog(

        document_id=document.id,

        document_name=document.name,

        action="create",

        result="success"

    )

    db.add(audit)

    db.commit()

    return document

# ============================================================

# ИЗМЕНЕНИЕ ДОКУМЕНТА

# ============================================================

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

    changed = (
        document.name != new_name
        or document.expires_at != new_expires_at
        or document.action != new_action
    )

    if not changed:
        return document

    document.name = new_name
    document.expires_at = new_expires_at
    document.action = new_action

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

# ============================================================

# УДАЛЕНИЕ ДОКУМЕНТА

# ============================================================

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

# ============================================================

# СКАЧИВАНИЕ

# ============================================================

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

    if not document.file_path:

        raise HTTPException(

            status_code=404,

            detail="У документа нет файла."

        )

    file_path = Path(

        document.file_path

    )

    if not file_path.exists():

        raise HTTPException(

            status_code=404,

            detail="Файл не найден."

        )

    return FileResponse(

        path=file_path,

        filename=document.name

    )

# ============================================================

# АУДИТ

# ============================================================

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

# ============================================================

# ОБРАБОТКА ИСТЁКШИХ ДОКУМЕНТОВ

# ============================================================

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

            # ------------------------------------------------
            # АРХИВИРОВАНИЕ
            # ------------------------------------------------
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
                    # Файл нельзя переместить — не скрываем проблему.
                    # Документ остаётся active, планировщик попробует снова.
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

            # ------------------------------------------------
            # УДАЛЕНИЕ
            # ------------------------------------------------
            elif document.action == "delete":

                if not document.file_path:
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

# ============================================================

# ПЛАНИРОВЩИК

# ============================================================

scheduler = BackgroundScheduler()

@app.on_event("startup")

def start_scheduler():

    if not scheduler.running:

        scheduler.add_job(

            process_expired_documents,

            "interval",

            minutes=1,

            id="process_expired_documents",

            replace_existing=True

        )

        scheduler.start()

        print(

            "Планировщик обработки сроков "

            "хранения запущен."

        )

@app.on_event("shutdown")

def stop_scheduler():

    if scheduler.running:

        scheduler.shutdown()

        print(

            "Планировщик остановлен."

        )
