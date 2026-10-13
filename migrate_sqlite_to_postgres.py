"""One-time import from a local OblivionDoc SQLite DB into an empty PostgreSQL DB.

Run from the project folder after installing requirements and setting DATABASE_URL
(to Neon/PostgreSQL) and optionally SQLITE_SOURCE (path to obliviondoc.db).
This script never deletes or modifies the source SQLite database.
"""

import os
import sqlite3
import hashlib
from pathlib import Path
from datetime import datetime, timezone

from sqlalchemy import DateTime, inspect, text

SOURCE_PATH = Path(os.getenv("SQLITE_SOURCE", "./obliviondoc.db")).expanduser().resolve()
TABLE_ORDER = [
    "users",
    "documents",
    "audit_logs",
    "password_reset_tokens",
    "organization_profiles",
]

def import_rows_into_empty_target(source_rows, target_engine, Base):
    """Copy prepared rows into an empty DB; exposed separately for local testing."""
    inspector = inspect(target_engine)
    target_tables = set(inspector.get_table_names())

    nonempty = []
    with target_engine.connect() as connection:
        for table in TABLE_ORDER:
            if table in target_tables:
                count = connection.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar_one()
                if count:
                    nonempty.append(f"{table} ({count})")
    if nonempty:
        raise RuntimeError(
            "Целевая база не пустая: " + ", ".join(nonempty) + ". Импорт остановлен без изменений."
        )

    imported = {}
    with target_engine.begin() as connection:
        inspector = inspect(target_engine)
        for table in TABLE_ORDER:
            rows = source_rows.get(table, [])
            if not rows or table not in Base.metadata.tables:
                imported[table] = 0
                continue
            target_column_names = {
                column["name"] for column in inspector.get_columns(table)
            }
            table_object = Base.metadata.tables[table]
            insert_keys = {
                key
                for row in rows
                for key in row
                if key in target_column_names
            }
            cleaned = []
            for row in rows:
                clean_row = {}
                for key in insert_keys:
                    value = row.get(key)
                    column = table_object.columns[key]
                    if value is not None and isinstance(column.type, DateTime) and isinstance(value, str):
                        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                        if value.tzinfo is not None:
                            value = value.astimezone(timezone.utc).replace(tzinfo=None)
                    clean_row[key] = value
                cleaned.append(clean_row)
            connection.execute(table_object.insert(), cleaned)
            imported[table] = len(cleaned)

        # Explicit primary-key IDs require PostgreSQL sequences to catch up.
        if target_engine.dialect.name == "postgresql":
            for table in TABLE_ORDER:
                if table in target_tables:
                    connection.execute(
                        text(
                            f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                            f"COALESCE((SELECT MAX(id) FROM {table}), 1), "
                            f"(SELECT COUNT(*) > 0 FROM {table}))"
                        )
                    )
    return imported

def main() -> None:
    if not SOURCE_PATH.is_file():
        raise SystemExit(
            f"Не найден файл SQLite: {SOURCE_PATH}\n"
            "Укажи путь через переменную SQLITE_SOURCE. Исходная база не изменена."
        )

    # Importing the application loads the SQLAlchemy models and applies its safe schema migration.
    from backend.database import engine as target_engine, Base
    from backend import models  # noqa: F401 - register all models in Base.metadata
    from backend.main import migrate_database

    if target_engine.dialect.name != "postgresql":
        raise SystemExit(
            "DATABASE_URL должен указывать на PostgreSQL/Neon, а не на SQLite."
        )

    Base.metadata.create_all(bind=target_engine)
    migrate_database()

    source = sqlite3.connect(str(SOURCE_PATH))
    source.row_factory = sqlite3.Row
    try:
        source_tables = {
            row[0]
            for row in source.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "users" not in source_tables:
            raise SystemExit("В SQLite-файле не найдена таблица users. База не импортирована.")

        source_rows = {}
        for table in TABLE_ORDER:
            if table in source_tables:
                source_rows[table] = [dict(row) for row in source.execute(f'SELECT * FROM "{table}"')]
            else:
                source_rows[table] = []

        # Revoke old reset links when changing databases; users can request a fresh one.
        source_rows["password_reset_tokens"] = []

        # The browser keeps its random token; the target database receives only its hash.
        for user in source_rows["users"]:
            token = user.get("session_token")
            if token:
                token = str(token)
                is_hash = len(token) == 64 and all(c in "0123456789abcdefABCDEF" for c in token)
                if not is_hash:
                    user["session_token"] = hashlib.sha256(token.encode("utf-8")).hexdigest()

        user_ids = [row.get("id") for row in source_rows["users"] if row.get("id") is not None]
        # Legacy versions sometimes created documents without an owner. Assign only when
        # the source has exactly one account; never guess if there is more than one.
        if len(user_ids) == 1:
            for doc in source_rows["documents"]:
                if not doc.get("user_id"):
                    doc["user_id"] = user_ids[0]

        # The old upload code stored files on disk. If the SQLite row has no binary copy,
        # capture the file now when its stored local path is still accessible.
        recovered = 0
        missing = 0
        project_dir = Path(__file__).resolve().parent
        for doc in source_rows["documents"]:
            if doc.get("file_content"):
                continue
            stored_path = doc.get("file_path")
            if not stored_path:
                continue
            candidate = Path(str(stored_path))
            candidates = [
                candidate,
                project_dir / "uploads" / candidate.name,
                project_dir / "archive" / candidate.name,
            ]
            available = next((path for path in candidates if path.is_file()), None)
            if available:
                try:
                    doc["file_content"] = available.read_bytes()
                    doc["file_name"] = doc.get("file_name") or available.name
                    recovered += 1
                except OSError:
                    available = None
            if not available:
                missing += 1
                # Avoid a dead download button for a file that cannot be recovered.
                doc["file_path"] = None
                doc["file_name"] = None

        # Do not merge with existing records: that could duplicate accounts or overwrite IDs.
        imported = import_rows_into_empty_target(source_rows, target_engine, Base)

        print("Импорт завершён.")
        for table, count in imported.items():
            print(f"  {table}: {count}")
        print(f"  Вложения, скопированные из локальной папки: {recovered}")
        if missing:
            print(
                f"  Вложений, которые не удалось найти на диске: {missing}. "
                "Записи сохранены, но эти файлы нужно восстановить из резервной копии, если она есть."
            )
        print("Исходный SQLite-файл не изменён. Не запускай импорт повторно без проверки целевой базы.")
    finally:
        source.close()

if __name__ == "__main__":
    main()
