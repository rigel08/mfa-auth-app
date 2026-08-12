"""
Encrypts TOTP secrets before they are stored in the database.

TOTP secrets are as sensitive as a password: anyone who reads one from the
database can generate valid codes for that user's account. We encrypt them
at rest with Fernet (AES-128-CBC + HMAC) using a key kept only in the
environment (MFA_ENCRYPTION_KEY), separate from the Flask SECRET_KEY.
"""
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def _fernet() -> Fernet:
    key = current_app.config.get("MFA_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "MFA_ENCRYPTION_KEY is not set. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_secret(plaintext_secret: str) -> str:
    return _fernet().encrypt(plaintext_secret.encode()).decode()


def decrypt_secret(ciphertext_secret: str) -> str:
    try:
        return _fernet().decrypt(ciphertext_secret.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Stored MFA secret could not be decrypted. Has MFA_ENCRYPTION_KEY changed?") from exc
