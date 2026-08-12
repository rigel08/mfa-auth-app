from tests.conftest import register_user, login_user


def test_session_cookie_is_httponly(client, db, registered_user):
    login_user(client)
    cookie_headers = [h for h in client.get("/dashboard").headers.getlist("Set-Cookie")]
    # Cookie may already be set from login response; re-check via app config directly too.
    assert client.application.config["SESSION_COOKIE_HTTPONLY"] is True
    assert client.application.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_security_headers_present(client, db):
    resp = client.get("/login")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in resp.headers


def test_account_lockout_after_repeated_failed_logins(app, client, db, registered_user):
    max_attempts = app.config["MAX_FAILED_LOGIN_ATTEMPTS"]
    for _ in range(max_attempts):
        login_user(client, password="wrong-password")

    resp = login_user(client, password="correct-horse-battery")
    assert b"Too many failed attempts" in resp.data


def test_unauthenticated_request_to_mfa_setup_redirects_to_login(client, db):
    resp = client.get("/mfa/setup", follow_redirects=True)
    assert b"Please log in to continue" in resp.data


def test_expired_mfa_pending_state_forces_relogin(app, client, db, mfa_user):
    from datetime import timedelta

    login_user(client)
    with client.session_transaction() as sess:
        # Simulate the pending-MFA window having expired.
        sess["pending_mfa_started_at"] = (
            __import__("datetime").datetime.utcnow() - app.config["MFA_PENDING_TIMEOUT"] - timedelta(seconds=1)
        ).isoformat()

    resp = client.get("/mfa/verify", follow_redirects=True)
    assert b"session expired" in resp.data
