"""Protections that apply to every request: CSRF tokens and response headers."""

import hmac
import secrets
from functools import wraps

from flask import abort, current_app, g, redirect, request, session, url_for

CONTENT_SECURITY_POLICY = "; ".join(
    [
        # Nothing is allowed unless listed. No script source is listed, so the
        # browser runs no script at all, injected or otherwise.
        "default-src 'none'",
        "style-src 'self'",
        "img-src 'self' data:",
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    ]
)


def csrf_token():
    """The token every form must send back, created on first use."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def check_csrf():
    """Refuse a state-changing request that does not carry the session's token.

    Another site can make a visitor's browser send a request here, cookie
    included, but it cannot read the token out of this site's pages.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    expected = session.get("csrf", "")
    sent = request.form.get("csrf_token", "")
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        abort(400, description="csrf")


def set_security_headers(response):
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.endpoint != "static":
        # Pages hold account details and one-time secrets; keep them out of
        # browser and proxy caches, and off the Back button after logout.
        response.headers["Cache-Control"] = "no-store"
    if current_app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped
