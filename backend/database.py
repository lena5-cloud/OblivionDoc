import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

raw_database_url = os.getenv("DATABASE_URL", "").strip()
is_render = bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))

if is_render and not raw_database_url:
    raise RuntimeError(

    )

DATABASE_URL = raw_database_url or "sqlite:///./obliviondoc.db"

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
