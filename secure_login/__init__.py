"""A small web app demonstrating a secure login system."""

import os
import secrets
from datetime import datetime, timezone

from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db, security, views
from .passwords import Passwords

__version__ = "1.0.0"

ERROR_PAGES = {
    400: ("Request not accepted", "The request was not valid."),
    404: ("Page not found", "There is nothing at this address."),
    405: ("Not allowed", "This page cannot be used that way."),
    413: ("Too much data", "The request was larger than this site accepts."),
    500: ("Something went wrong", "The error is on our side. Try again in a moment."),
}
CSRF_MESSAGE = (
    "The form you sent had expired or did not come from this site."
    " Go back, reload the page and try again."
)


def _load_secret_key(instance_path):
    """The key that signs the session cookie.

    Taken from the environment when set. Otherwise one is generated on first
    run and kept in the instance folder, which is not part of the repository.
    """
    key = os.environ.get("SECURE_LOGIN_SECRET_KEY")
    if key:
        return key
    path = os.path.join(instance_path, "secret_key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, encoding="ascii") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(key)
    return key


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)
    app.config.update(
        DATABASE=os.environ.get("SECURE_LOGIN_DB")
        or os.path.join(app.instance_path, "secure_login.db"),
        # The cookie is sent over HTTPS only, hidden from scripts, and left
        # out of requests that other sites make.
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_IDLE_SECONDS=30 * 60,
        SESSION_MAX_SECONDS=12 * 60 * 60,
        MAX_CONTENT_LENGTH=64 * 1024,
        ARGON2_PARAMS={},
        TRUSTED_PROXIES=int(os.environ.get("SECURE_LOGIN_PROXIES", "0")),
    )
    app.config.update(config or {})
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_secret_key(app.instance_path)
    if app.config["SESSION_COOKIE_SECURE"]:
        # The __Host- prefix makes browsers refuse the cookie unless it is
        # Secure and bound to exactly this host, so a sibling subdomain
        # cannot overwrite it.
        app.config["SESSION_COOKIE_NAME"] = "__Host-session"
    if app.config["TRUSTED_PROXIES"]:
        # Behind a reverse proxy the client address and scheme arrive in
        # headers. They are believed only for the stated number of proxies.
        hops = app.config["TRUSTED_PROXIES"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)

    app.extensions["passwords"] = Passwords(**app.config["ARGON2_PARAMS"])
    db.init_db(app)
    app.teardown_appcontext(db.close_db)

    app.before_request(security.check_csrf)
    app.before_request(views.load_user)
    app.after_request(security.set_security_headers)
    app.register_blueprint(views.bp)

    app.jinja_env.globals["csrf_token"] = security.csrf_token

    @app.template_filter("datetime")
    def format_datetime(timestamp):
        moment = datetime.fromtimestamp(timestamp, timezone.utc)
        return moment.strftime("%Y-%m-%d %H:%M UTC")

    def error_page(error):
        code = error.code if error.code in ERROR_PAGES else 500
        title, message = ERROR_PAGES[code]
        if code == 400 and error.description == "csrf":
            message = CSRF_MESSAGE
        return render_template("error.html", title=title, message=message), code

    for code in ERROR_PAGES:
        app.register_error_handler(code, error_page)

    return app
