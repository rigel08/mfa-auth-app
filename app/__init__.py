import logging
import os

from flask import Flask, render_template

from app.config import get_config
from app.extensions import db, csrf, limiter


def create_app(config_object=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object or get_config())

    _validate_required_config(app)

    os.makedirs(app.instance_path, exist_ok=True)

    # A bare "sqlite:///instance/app.db" is resolved relative to the process's
    # current working directory, which breaks depending on where the app is
    # launched from. Anchor it to Flask's actual instance folder instead.
    db_uri = app.config["SQLALCHEMY_DATABASE_URI"]
    if db_uri.startswith("sqlite:///") and not db_uri.startswith("sqlite:////"):
        relative_path = db_uri[len("sqlite:///"):]
        if relative_path != ":memory:":
            absolute_path = os.path.join(app.instance_path, os.path.basename(relative_path))
            app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{absolute_path}"

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    _configure_logging(app)
    _register_security_headers(app)
    _register_error_handlers(app)

    from app.auth.routes import auth_bp
    from app.mfa.routes import mfa_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(mfa_bp)

    with app.app_context():
        db.create_all()

    return app


def _validate_required_config(app):
    """Fail fast at startup instead of silently running with broken/missing secrets."""
    if app.config.get("TESTING"):
        return
    missing = [k for k in ("SECRET_KEY", "MFA_ENCRYPTION_KEY") if not app.config.get(k)]
    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            "Copy .env.example to .env and fill them in."
        )


def _configure_logging(app):
    level = logging.DEBUG if app.debug else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Never log secrets, passwords, tokens, or full request bodies.


def _register_security_headers(app):
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


def _register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(_e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(_e):
        # Never leak stack traces or internals to the client.
        app.logger.exception("Unhandled server error")
        return render_template("errors/500.html"), 500

    @app.errorhandler(429)
    def rate_limited(_e):
        return render_template("errors/429.html"), 429
