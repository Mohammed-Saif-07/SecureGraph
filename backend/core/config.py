from functools import cached_property
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "password"
    postgres_url: str = "postgresql+psycopg://user:pass@localhost:5432/securegraph"
    redis_url: str = "redis://localhost:6379"
    groq_api_key: str = ""
    github_token: str = ""
    nvd_api_key: str = ""
    jwt_secret: str = "dev-only-change-me"
    access_token_minutes: int = 30
    refresh_token_days: int = 14
    auth_required: bool = False
    rate_limit_enabled: bool = True
    scan_rate_limit_per_day: int = 100
    query_rate_limit_per_day: int = 1000
    cors_origins_raw: str = Field(default="http://localhost:5173", validation_alias="CORS_ORIGINS")

    @cached_property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins_raw.split(",") if origin.strip()]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
