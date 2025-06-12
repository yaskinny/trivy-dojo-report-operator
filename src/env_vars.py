import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

def get_required_env_var(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        logger.error(f"Required environment variable '{name}' is not set")
        raise SystemExit(1)
    return value

def get_env_var_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return value.lower() == "true" if value is not None else default

def get_env_var_list(name: str, default: list[str] = None) -> list[str]:
    value = os.getenv(name)
    return value.split(",") if value else (default or [])
