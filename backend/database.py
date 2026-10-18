import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

raw_database_url = os.getenv("DATABASE_URL", "").strip()
is_render = bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))

if is_render:
    if not raw_database_url:
        raise RuntimeError("DATABASE_URL должен быть задан в настройках Render.")
    DATABASE_URL = raw_database_url
else:
    DATABASE_URL = os.getenv(
        "OBLIVION_TEST_DATABASE_URL",
        "sqlite:///./obliviondoc_test.db"
    ).strip()
    if not DATABASE_URL.startswith("sqlite:"):
        raise RuntimeError(
            "Локальная тестовая копия использует только SQLite. "
            "Проверьте OBLIVION_TEST_DATABASE_URL."
        )

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://", "postgresql+psycopg://", 1
    )
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgresql://", "postgresql+psycopg://", 1
    )

engine_options = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_options)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
