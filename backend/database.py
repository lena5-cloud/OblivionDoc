from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Подключение к базе данных SQLite
DATABASE_URL = "sqlite:///./obliviondoc.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Создаём фабрику сессий для работы с базой
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Базовый класс для моделей таблиц
Base = declarative_base()


# Функция для получения соединения с базой
def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
