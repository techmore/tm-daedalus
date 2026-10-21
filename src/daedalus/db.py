from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from daedalus.config import DATABASE_URL


class Base(DeclarativeBase):
    pass


if DATABASE_URL.startswith("sqlite:///"):
    sqlite_path = DATABASE_URL.removeprefix("sqlite:///")
    if sqlite_path != ":memory:" and not sqlite_path.startswith("/"):
        Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)

SQLITE_BUSY_TIMEOUT_MS = 30_000


def configure_sqlite_connection(connection, _record=None) -> None:
    """Foreign keys, a bounded lock wait, and WAL so readers do not block the writer.

    The portal assumes ONE uvicorn worker: WAL needs shared memory on a local
    filesystem, and the live hub, schedulers and report threads are per-process.
    """
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    if not DATABASE_URL.startswith("sqlite:///:memory:"):
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


if DATABASE_URL.startswith("sqlite"):
    event.listens_for(engine, "connect")(configure_sqlite_connection)


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
