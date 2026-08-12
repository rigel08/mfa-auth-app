from datetime import datetime, timedelta

from flask import Blueprint, render_template, redirect, url_for, flash, current_app

from app.extensions import db, limiter
from app.models import User
from app.auth.forms import RegisterForm, LoginForm
from app.auth_state import (
    login_required,
    anonymous_required,
    current_user_id,
    start_mfa_pending,
    complete_login,
    logout as clear_session,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    if current_user_id():
        return redirect(url_for("auth.dashboard"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
@anonymous_required
@limiter.limit(lambda: current_app.config["RATE_LIMIT_REGISTER"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()

        if User.query.filter_by(email=email).first():
            # Same message as an unrelated validation failure would be even better for
            # enumeration resistance, but a distinct "already registered" message is a
            # deliberate, common trade-off for usability. Documented in README limitations.
            flash("An account with that email already exists.", "error")
            return render_template("register.html", form=form)

        user = User(email=email)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash("Account created. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@anonymous_required
@limiter.limit(lambda: current_app.config["RATE_LIMIT_LOGIN"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()

        # Deliberately identical error message + always hash-compare to avoid
        # leaking, via timing or message content, whether the email exists.
        generic_error = "Invalid email or password."

        if user and user.is_login_locked():
            flash("Too many failed attempts. Try again later.", "error")
            return render_template("login.html", form=form)

        password_ok = user.check_password(form.password.data) if user else False

        if not user or not password_ok:
            if user:
                _register_failed_login(user)
            flash(generic_error, "error")
            return render_template("login.html", form=form)

        # Correct password.
        _reset_failed_login(user)

        if user.mfa_enabled:
            start_mfa_pending(user.id)
            return redirect(url_for("mfa.verify"))

        user.last_login_at = datetime.utcnow()
        db.session.commit()
        complete_login(user.id)
        return redirect(url_for("auth.dashboard"))

    return render_template("login.html", form=form)


def _register_failed_login(user: User) -> None:
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= current_app.config["MAX_FAILED_LOGIN_ATTEMPTS"]:
        user.login_locked_until = datetime.utcnow() + timedelta(
            minutes=current_app.config["LOGIN_LOCKOUT_MINUTES"]
        )
        user.failed_login_attempts = 0
    db.session.commit()


def _reset_failed_login(user: User) -> None:
    user.failed_login_attempts = 0
    user.login_locked_until = None
    db.session.commit()


@auth_bp.route("/logout", methods=["POST"])
def logout():
    clear_session()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/dashboard")
@login_required
def dashboard():
    user = db.session.get(User, current_user_id())
    if not user:
        clear_session()
        return redirect(url_for("auth.login"))
    return render_template("dashboard.html", user=user)
