import os
from datetime import timedelta


def _bool_env(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


class Config:
    """Base configuration. Values come from environment variables — never hardcode secrets here."""

    SECRET_KEY = os.getenv("SECRET_KEY")
    MFA_ENCRYPTION_KEY = os.getenv("MFA_ENCRYPTION_KEY")

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///instance/app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session / cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool_env("SESSION_COOKIE_SECURE", "false")
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_REFRESH_EACH_REQUEST = True

    # A short-lived window for the "password verified, MFA pending" state,
    # so an abandoned login can't be resumed indefinitely.
    MFA_PENDING_TIMEOUT = timedelta(minutes=5)

    WTF_CSRF_TIME_LIMIT = None  # tie CSRF token lifetime to the session instead of a fixed window

    RATE_LIMIT_LOGIN = os.getenv("RATE_LIMIT_LOGIN", "10 per minute")
    RATE_LIMIT_REGISTER = os.getenv("RATE_LIMIT_REGISTER", "5 per minute")
    RATE_LIMIT_MFA_VERIFY = os.getenv("RATE_LIMIT_MFA_VERIFY", "10 per minute")
    RATE_LIMIT_MFA_SETUP = os.getenv("RATE_LIMIT_MFA_SETUP", "5 per minute")

    # Account lockout thresholds
    MAX_FAILED_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_MINUTES = 15
    MAX_FAILED_MFA_ATTEMPTS = 5
    MFA_LOCKOUT_MINUTES = 15


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False  # simplifies posting forms in tests; app-level CSRF still covers real usage
    RATELIMIT_ENABLED = False
    # Fixed, non-secret values for the test suite only. Never reuse these outside tests.
    SECRET_KEY = "test-secret-key-not-for-real-use"
    MFA_ENCRYPTION_KEY = "0VUmmHVXsLebSTVSRcEAf_GJp6E4K4toH9JnS-xQzKU="


def get_config():
    env = os.getenv("FLASK_ENV", "development").lower()
    if env == "production":
        return ProductionConfig
    if env == "testing":
        return TestingConfig
    return DevelopmentConfig
