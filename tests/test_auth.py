from tests.conftest import register_user, login_user


def test_register_creates_user(client, db):
    resp = register_user(client)
    assert resp.status_code == 200
    assert b"You can now log in" in resp.data


def test_duplicate_registration_rejected(client, db):
    register_user(client)
    resp = register_user(client)
    assert b"already exists" in resp.data


def test_password_is_hashed_not_stored_plaintext(app, client, db):
    register_user(client)
    from app.models import User

    with app.app_context():
        user = User.query.filter_by(email="user@example.com").first()
        assert user.password_hash != "correct-horse-battery"
        assert user.password_hash.startswith("scrypt:") or ":" in user.password_hash


def test_login_success_without_mfa_reaches_dashboard(client, db, registered_user):
    resp = login_user(client)
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data
    assert b"Fully authenticated" in resp.data


def test_login_invalid_password_rejected(client, db, registered_user):
    resp = login_user(client, password="wrong-password")
    assert b"Invalid email or password" in resp.data
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_login_unknown_email_gives_generic_error(client, db):
    resp = login_user(client, email="nobody@example.com", password="whatever123")
    assert b"Invalid email or password" in resp.data


def test_logout_clears_session(client, db, registered_user):
    login_user(client)
    client.post("/logout")
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_dashboard_requires_login(client, db):
    resp = client.get("/dashboard", follow_redirects=True)
    assert b"Please log in to continue" in resp.data


def test_dashboard_inaccessible_after_logout(client, db, registered_user):
    login_user(client)
    client.post("/logout")
    resp = client.get("/dashboard", follow_redirects=True)
    assert b"Please log in to continue" in resp.data
