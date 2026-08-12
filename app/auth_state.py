"""
Authentication state model.

    Unauthenticated
          |
    Password Verified   (session['pending_mfa_user_id'] set, MFA required)
          |
    MFA Verified / Not Required
          |
    Fully Authenticated  (session['user_id'] set)

`session['user_id']` is the ONLY thing that means "fully authenticated."
A user who has passed the password check but still owes an MFA code is
represented by `session['pending_mfa_user_id']` — a completely separate
key — and `@login_required` never accepts it. This is what stops
"password correct" from being treated as "logged in."
"""
from datetime import datetime, timedelta
from functools import wraps

from flask import session, redirect, url_for, flash, current_app


def start_mfa_pending(user_id: int) -> None:
    """Called right after a correct password. Does NOT log the user in."""
    session.clear()
    session["pending_mfa_user_id"] = user_id
    session["pending_mfa_started_at"] = datetime.utcnow().isoformat()


def pending_mfa_user_id():
    """Returns the user id awaiting MFA, or None if there isn't one / it expired."""
    user_id = session.get("pending_mfa_user_id")
    started_at = session.get("pending_mfa_started_at")
    if not user_id or not started_at:
        return None

    timeout = current_app.config["MFA_PENDING_TIMEOUT"]
    if datetime.utcnow() - datetime.fromisoformat(started_at) > timeout:
        clear_mfa_pending()
        return None
    return user_id


def clear_mfa_pending() -> None:
    session.pop("pending_mfa_user_id", None)
    session.pop("pending_mfa_started_at", None)


def complete_login(user_id: int) -> None:
    """Called only once the user is fully authenticated (password, and MFA if enabled)."""
    session.clear()
    session["user_id"] = user_id
    session.permanent = True


def current_user_id():
    return session.get("user_id")


def logout() -> None:
    session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user_id():
            flash("Please log in to continue.", "error")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


def anonymous_required(view):
    """Redirect already-authenticated users away from login/register pages."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user_id():
            return redirect(url_for("auth.dashboard"))
        return view(*args, **kwargs)

    return wrapped
