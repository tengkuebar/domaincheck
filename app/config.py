from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration from DOMAINCHECK_* environment variables. No secrets live in the repo."""

    model_config = SettingsConfigDict(env_prefix="DOMAINCHECK_", env_file=".env", extra="ignore")

    # If unset, a random key is generated at startup (only the CSRF cookie depends on it).
    secret_key: str | None = None
    session_ttl_seconds: int = 8 * 3600
    secure_cookies: bool = True
    hsts: bool = True
    # Behind a single trusted proxy (Fly, Render, ...) the real client is the last X-Forwarded-For.
    trust_forwarded_for: bool = False
    # Requests sensitive file paths (/.git/HEAD, /.env, ...) on the target. Off by default
    # because the app no longer proves the user owns the domain.
    enable_path_check: bool = False
    # Per-IP, per-domain and global scan limits per hour.
    limit_ip_per_hour: int = 10
    limit_domain_per_hour: int = 3
    limit_global_per_hour: int = 120
