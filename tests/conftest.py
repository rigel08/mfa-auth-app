import pyotp
import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db as _db
from app.models import User


@pytest.fixture()
def app():
    application = create_app(TestingConfig)
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db(app):
    with app.app_context():
        yield _db
        _db.session.remove()
        _db.drop_all()
        _db.create_all()


def register_user(client, email="user@example.com", password="correct-horse-battery"):
    return client.post(
        "/register",
        data={"email": email, "password": password, "confirm_password": password},
        follow_redirects=True,
    )


def login_user(client, email="user@example.com", password="correct-horse-battery"):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)


@pytest.fixture()
def registered_user(app, db, client):
    register_user(client)
    with app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        return user.id


@pytest.fixture()
def mfa_user(app, db, client, registered_user):
    """A user with MFA already enabled; returns (user_id, raw_totp_secret)."""
    login_user(client)
    resp = client.get("/mfa/setup")
    assert resp.status_code == 200

    with client.session_transaction() as sess:
        secret = sess["pending_mfa_secret"]

    totp = pyotp.TOTP(secret)
    client.post("/mfa/setup", data={"code": totp.now()}, follow_redirects=True)
    client.post("/logout")
    return registered_user, secret
