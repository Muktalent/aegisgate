import os
from pathlib import Path


project_root = Path(__file__).resolve().parent.parent
env_file = project_root / ".env"


def load_env_file() -> None:
    if not env_file.exists():
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", maxsplit=1)
        os.environ.setdefault(key.strip(), value.strip())


load_env_file()


ENVIRONMENT = os.getenv("AEGIS_ENVIRONMENT", "development")
JWT_SECRET = os.getenv("AEGIS_JWT_SECRET", "")
AUDIT_HMAC_KEY = os.getenv("AEGIS_AUDIT_HMAC_KEY", "")
JWT_ALGORITHM = os.getenv("AEGIS_JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("AEGIS_ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)

INGESTOR_USERNAME = os.getenv("AEGIS_INGESTOR_USERNAME", "")
INGESTOR_PASSWORD = os.getenv("AEGIS_INGESTOR_PASSWORD", "")
SOC_USERNAME = os.getenv("AEGIS_SOC_USERNAME", "")
SOC_PASSWORD = os.getenv("AEGIS_SOC_PASSWORD", "")
ADMIN_USERNAME = os.getenv("AEGIS_ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("AEGIS_ADMIN_PASSWORD", "")