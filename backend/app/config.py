from pydantic_settings import BaseSettings, SettingsConfigDict

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
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
