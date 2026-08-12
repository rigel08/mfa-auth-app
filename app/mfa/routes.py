import base64
import io
from datetime import datetime, timedelta

import pyotp
import qrcode
from flask import Blueprint, render_template, redirect, url_for, flash, session, current_app

from app.extensions import db, limiter
from app.models import User
from app.auth.forms import MfaCodeForm
from app.crypto import encrypt_secret, decrypt_secret
from app.auth_state import (
    login_required,
    current_user_id,
    pending_mfa_user_id,
    clear_mfa_pending,
    complete_login,
    logout as clear_session,
)

mfa_bp = Blueprint("mfa", __name__, url_prefix="/mfa")


# ---------------------------------------------------------------------------
# Setup (performed by an already fully-authenticated user, from the dashboard)
# ---------------------------------------------------------------------------

@mfa_bp.route("/setup", methods=["GET", "POST"])
@login_required
@limiter.limit(lambda: current_app.config["RATE_LIMIT_MFA_SETUP"])
def setup():
    user = db.session.get(User, current_user_id())
    if not user:
        clear_session()
        return redirect(url_for("auth.login"))

    if user.mfa_enabled:
        flash("MFA is already enabled on your account.", "info")
        return redirect(url_for("auth.dashboard"))

    form = MfaCodeForm()

    # Generate a fresh secret once per setup attempt and hold it in the
    # session only until it's confirmed — nothing touches the database
    # until the user proves they can produce a valid code with it.
    pending_secret = session.get("pending_mfa_secret")
    if not pending_secret:
        pending_secret = pyotp.random_base32()
        session["pending_mfa_secret"] = pending_secret

    if form.validate_on_submit():
        totp = pyotp.TOTP(pending_secret)
        if totp.verify(form.code.data.strip(), valid_window=1):  # allows +/-1 step (~30s) of clock skew
            user.mfa_secret_encrypted = encrypt_secret(pending_secret)
            user.mfa_enabled = True
            db.session.commit()
            session.pop("pending_mfa_secret", None)
            flash("MFA has been enabled on your account.", "success")
            return redirect(url_for("auth.dashboard"))
        flash("That code didn't match. Check your authenticator app and try again.", "error")

    uri = pyotp.TOTP(pending_secret).provisioning_uri(name=user.email, issuer_name="MFA Auth App")
    qr_data_uri = _qr_data_uri(uri)

    return render_template(
        "mfa_setup.html", form=form, qr_data_uri=qr_data_uri, manual_secret=pending_secret
    )


@mfa_bp.route("/setup/cancel", methods=["POST"])
@login_required
def cancel_setup():
    session.pop("pending_mfa_secret", None)
    flash("MFA setup cancelled.", "info")
    return redirect(url_for("auth.dashboard"))


@mfa_bp.route("/disable", methods=["POST"])
@login_required
def disable():
    user = db.session.get(User, current_user_id())
    if not user:
        clear_session()
        return redirect(url_for("auth.login"))

    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    db.session.commit()
    flash("MFA has been disabled on your account.", "success")
    return redirect(url_for("auth.dashboard"))


# ---------------------------------------------------------------------------
# Verification (performed mid-login, before the session is fully authenticated)
# ---------------------------------------------------------------------------

@mfa_bp.route("/verify", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["RATE_LIMIT_MFA_VERIFY"])
def verify():
    user_id = pending_mfa_user_id()
    if not user_id:
        flash("Your login session expired. Please log in again.", "error")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user or not user.mfa_enabled or not user.mfa_secret_encrypted:
        # Defensive: this state should be unreachable, but never let a
        # user without a valid MFA secret slip past this checkpoint.
        clear_mfa_pending()
        flash("MFA verification could not be completed. Please log in again.", "error")
        return redirect(url_for("auth.login"))

    if user.is_mfa_locked():
        flash("Too many failed codes. Try again later.", "error")
        return render_template("mfa_verify.html", form=MfaCodeForm())

    form = MfaCodeForm()
    if form.validate_on_submit():
        secret = decrypt_secret(user.mfa_secret_encrypted)
        totp = pyotp.TOTP(secret)

        if totp.verify(form.code.data.strip(), valid_window=1):
            user.failed_mfa_attempts = 0
            user.mfa_locked_until = None
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            clear_mfa_pending()
            complete_login(user.id)
            return redirect(url_for("auth.dashboard"))

        user.failed_mfa_attempts += 1
        if user.failed_mfa_attempts >= current_app.config["MAX_FAILED_MFA_ATTEMPTS"]:
            user.mfa_locked_until = datetime.utcnow() + timedelta(
                minutes=current_app.config["MFA_LOCKOUT_MINUTES"]
            )
            user.failed_mfa_attempts = 0
        db.session.commit()
        flash("Invalid code. Please try again.", "error")

    return render_template("mfa_verify.html", form=form)


def _qr_data_uri(provisioning_uri: str) -> str:
    img = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{encoded}"
