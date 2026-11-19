# MFA Auth App

A Flask learning project exploring password authentication and time-based one-time passwords (TOTP).

## Features

- Registration and password login
- Authenticator enrollment with QR codes
- Separate password-verified and fully authenticated session states
- Encrypted TOTP secrets at rest
- CSRF protection, rate limits, and account lockout
- Automated authentication, MFA, and security tests

## Run locally

```sh
git clone https://github.com/rigel08/mfa-auth-app.git
cd mfa-auth-app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Generate your own keys and put them in `.env`:

```sh
python -c "import secrets; print(secrets.token_hex(32))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Use the first value for `SECRET_KEY` and the second for `MFA_ENCRYPTION_KEY`. Keep both private. Then run:

```sh
python run.py
```

Open http://127.0.0.1:5000. Register, sign in, and enroll an authenticator from the dashboard. SQLite tables are created at startup.

## Tests

```sh
python -m pytest -q
```

## Implementation

`app/auth/` handles registration and login; `app/mfa/` handles enrollment and verification. `app/auth_state.py` manages session state, and `app/crypto.py` encrypts stored TOTP secrets.

## Limitations

This is an educational project, not an audited identity provider. Registration reveals whether an email already exists. MFA disabling currently relies on the existing authenticated session, without fresh password or TOTP verification. Recovery codes and database migration tooling are not implemented. Review these flows before any real deployment.
