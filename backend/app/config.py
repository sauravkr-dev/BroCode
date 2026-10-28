import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# Determine absolute paths to project directories
BACKEND_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BACKEND_DIR.parent

# Env file search order:
# 1. ROOT_DIR / ".env" (repository root .env)
# 2. BACKEND_DIR / ".env" (backend/.env, takes precedence so edits here apply regardless of CWD)
# 3. Current working directory .env if distinct
_candidate_env_files = [
    str(ROOT_DIR / ".env"),
    str(BACKEND_DIR / ".env"),
]
_cwd_env = str(Path(".env").resolve())
if _cwd_env not in _candidate_env_files:
    _candidate_env_files.insert(0, _cwd_env)


class Settings(BaseSettings):
    app_name: str = "BroCode Compliance Screening"
    environment: str = "development"
    database_url: str = "sqlite:///./brocode.db"
    secret_key: str = "CHANGE-ME"
    access_token_minutes: int = 45
    cors_origins: str = "http://localhost:5173"
    upload_dir: str = "./uploads"
    max_upload_mb: int = 12
    seed_demo_users: bool = False
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_fallback_model: str = ""
    gemini_max_retries: int = 1
    gemini_timeout_seconds: float = 10.0
    model_config = SettingsConfigDict(
        env_file=_candidate_env_files,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()


def get_model_config_diagnostics() -> dict:
    """
    Returns diagnostics explaining how Gemini model settings were resolved:
    - effective primary model
    - effective fallback model
    - whether environment-variable overrides (os.environ) are active
    - which .env files exist and were loaded
    - whether an API key is configured (never exposes the key)
    """
    env_override_primary = os.environ.get("GEMINI_MODEL")
    env_override_fallback = os.environ.get("GEMINI_FALLBACK_MODEL")
    existing_env_files = [f for f in _candidate_env_files if Path(f).is_file()]

    return {
        "effective_primary_model": settings.gemini_model,
        "effective_fallback_model": settings.gemini_fallback_model or None,
        "env_var_override_primary": env_override_primary,
        "env_var_override_fallback": env_override_fallback,
        "is_overridden_by_env": env_override_primary is not None or env_override_fallback is not None,
        "inspected_env_files": _candidate_env_files,
        "loaded_env_files": existing_env_files,
        "api_key_configured": bool(settings.gemini_api_key.strip()),
    }

