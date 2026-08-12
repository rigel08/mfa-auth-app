from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db


def utcnow():
    # Naive UTC datetime, matched consistently on both write and read.
    # (SQLite has no native timezone-aware datetime type, so mixing aware
    # and naive datetimes here would break comparisons like is_login_locked().)
    return datetime.utcnow()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    # Encrypted at rest (see app/crypto.py). Null until MFA setup begins.
    mfa_secret_encrypted = db.Column(db.String(255), nullable=True)

    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    login_locked_until = db.Column(db.DateTime, nullable=True)

    failed_mfa_attempts = db.Column(db.Integer, default=0, nullable=False)
    mfa_locked_until = db.Column(db.DateTime, nullable=True)

    last_login_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def set_password(self, raw_password: str) -> None:
        # Werkzeug's default (scrypt, as of Werkzeug 2.3+) is a modern,
        # memory-hard KDF suitable for password storage.
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    def is_login_locked(self) -> bool:
        return bool(self.login_locked_until and self.login_locked_until > utcnow())

    def is_mfa_locked(self) -> bool:
        return bool(self.mfa_locked_until and self.mfa_locked_until > utcnow())

    def __repr__(self):
        return f"<User id={self.id} email={self.email!r}>"
