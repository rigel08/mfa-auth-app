import pyotp

from tests.conftest import login_user


def test_mfa_setup_generates_qr_and_secret(client, db, registered_user):
    login_user(client)
    resp = client.get("/mfa/setup")
    assert resp.status_code == 200
    assert b"data:image/png;base64," in resp.data
    with client.session_transaction() as sess:
        assert "pending_mfa_secret" in sess


def test_mfa_not_enabled_until_valid_code_confirmed(app, client, db, registered_user):
    login_user(client)
    client.get("/mfa/setup")
    with client.session_transaction() as sess:
        secret = sess["pending_mfa_secret"]

    from app.models import User

    with app.app_context():
        user = User.query.get(registered_user)
        assert user.mfa_enabled is False

    totp = pyotp.TOTP(secret)
    client.post("/mfa/setup", data={"code": totp.now()}, follow_redirects=True)

    with app.app_context():
        user = User.query.get(registered_user)
        assert user.mfa_enabled is True
        # secret must not be stored in plaintext
        assert user.mfa_secret_encrypted != secret


def test_mfa_setup_rejects_invalid_code(app, client, db, registered_user):
    login_user(client)
    client.get("/mfa/setup")
    resp = client.post("/mfa/setup", data={"code": "000000"}, follow_redirects=True)
    assert b"match" in resp.data and b"Check your authenticator" in resp.data
    from app.models import User

    with app.app_context():
        user = User.query.get(registered_user)
        assert user.mfa_enabled is False


def test_login_with_mfa_enabled_requires_otp_step(client, db, mfa_user):
    user_id, secret = mfa_user
    resp = login_user(client)
    # Password alone should NOT reach the dashboard.
    assert b"Dashboard" not in resp.data
    assert b"Enter your code" in resp.data
    with client.session_transaction() as sess:
        assert "user_id" not in sess
        assert sess.get("pending_mfa_user_id") == user_id


def test_valid_otp_completes_login(client, db, mfa_user):
    user_id, secret = mfa_user
    login_user(client)
    totp = pyotp.TOTP(secret)
    resp = client.post("/mfa/verify", data={"code": totp.now()}, follow_redirects=True)
    assert b"Dashboard" in resp.data
    with client.session_transaction() as sess:
        assert sess.get("user_id") == user_id


def test_invalid_otp_rejected(client, db, mfa_user):
    login_user(client)
    resp = client.post("/mfa/verify", data={"code": "000000"}, follow_redirects=True)
    assert b"Invalid code" in resp.data
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_cannot_bypass_mfa_by_hitting_dashboard_directly(client, db, mfa_user):
    login_user(client)  # password verified, MFA still pending
    resp = client.get("/dashboard", follow_redirects=True)
    assert b"Please log in to continue" in resp.data


def test_mfa_disable(app, client, db, mfa_user):
    user_id, secret = mfa_user
    login_user(client)
    totp = pyotp.TOTP(secret)
    client.post("/mfa/verify", data={"code": totp.now()}, follow_redirects=True)

    resp = client.post("/mfa/disable", follow_redirects=True)
    assert b"MFA has been disabled" in resp.data

    from app.models import User

    with app.app_context():
        user = User.query.get(user_id)
        assert user.mfa_enabled is False
        assert user.mfa_secret_encrypted is None
