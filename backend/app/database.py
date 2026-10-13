import os
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


APP_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = APP_DIR.parents[1]
DEFAULT_DATABASE_PATH = APP_DIR / "aegisgate.db"

configured_path = os.environ.get("AEGISGATE_DATABASE_PATH")

if configured_path is None:
    DATABASE_PATH = DEFAULT_DATABASE_PATH
else:
    if not configured_path.strip():
        raise ValueError("AEGISGATE_DATABASE_PATH must not be empty.")

    DATABASE_PATH = Path(configured_path).expanduser()

    if not DATABASE_PATH.is_absolute():
        DATABASE_PATH = PROJECT_ROOT / DATABASE_PATH

    DATABASE_PATH = DATABASE_PATH.resolve()

    if not DATABASE_PATH.is_file():
        raise FileNotFoundError(
            "Configured database does not exist: "
            f"{DATABASE_PATH}"
        )

DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()