"""The pages: registration, login, the two-factor step, account and logout."""

import math
import sqlite3
import time

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from . import sessions, throttle, twofactor, validation
from .db import get_db
from .security import login_required

# How long after the password the second factor may still be entered.
PENDING_2FA_SECONDS = 5 * 60
IDENTIFIER_MAX = validation.EMAIL_MAX
USER_AGENT_MAX = 200

bp = Blueprint("auth", __name__)


def _passwords():
    return current_app.extensions["passwords"]


def _client_ip():
    return request.remote_addr or "unknown"


def _too_many(wait_seconds):
    minutes = math.ceil(wait_seconds / 60)
    unit = "minute" if minutes == 1 else "minutes"
    return f"Too many failed attempts. Try again in {minutes} {unit}."


def load_user():
    """Find out who is making the request, from the session cookie."""
    g.user = None
    g.session_token = None
    if request.endpoint == "static":
        return
    token = session.get("sid")
    if not token:
        return
    db = get_db()
    row = sessions.load(
        db,
        token,
        current_app.config["SESSION_IDLE_SECONDS"],
        current_app.config["SESSION_MAX_SECONDS"],
    )
    if row is None:
        # Expired, or ended from elsewhere: the cookie is worthless now.
        session.clear()
        return
    g.user = db.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    g.session_token = token


def _start_session(user):
    """Log a user in.

    Everything from before the login is dropped and a new token is issued,
    so a session identifier planted in the browser beforehand gains nothing.
    """
    session.clear()
    session["sid"] = sessions.create(
        get_db(), user["id"], _client_ip(), request.user_agent.string[:USER_AGENT_MAX]
    )


def _find_user(db, identifier):
    if not identifier or len(identifier) > IDENTIFIER_MAX:
        return None
    return db.execute(
        "SELECT * FROM users WHERE username = ? OR email = ?",
        (identifier, identifier.lower()),
    ).fetchone()


def _password_matches(db, user, password):
    passwords = _passwords()
    if len(password) > validation.PASSWORD_MAX:
        return False
    if user is None:
        passwords.verify_dummy(password)
        return False
    if not passwords.verify(user["password_hash"], password):
        return False
    if passwords.needs_rehash(user["password_hash"]):
        # The cost parameters were raised since this hash was made.
        with db:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (passwords.hash(password), user["id"]),
            )
    return True


def _reauthenticate(password):
    """Ask for the password again before a sensitive change.

    Returns an error message, or None if the password is correct. A stolen
    session alone is then not enough to turn two-factor authentication off.
    """
    db = get_db()
    key = throttle.account_key(g.user, "")
    ip = _client_ip()
    wait = throttle.retry_after(db, key, ip)
    if wait:
        return _too_many(wait)
    if not _password_matches(db, g.user, password):
        throttle.record_failure(db, key, ip)
        return "That password is not correct."
    return None


@bp.route("/")
def index():
    return redirect(url_for("auth.account" if g.user else "auth.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("auth.account"))
    form = {"username": "", "email": ""}
    errors = {}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        form = {"username": username, "email": email}
        errors = validation.validate_registration(
            username, email, password, request.form.get("confirm", "")
        )
        db = get_db()
        if not errors:
            if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                errors["username"] = "That username is taken."
            if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                errors["email"] = "That email address is already registered."
        if not errors:
            try:
                with db:
                    db.execute(
                        "INSERT INTO users (username, email, password_hash, created_at)"
                        " VALUES (?, ?, ?, ?)",
                        (username, email, _passwords().hash(password), int(time.time())),
                    )
            except sqlite3.IntegrityError:
                # Someone registered the same name between the check and the insert.
                errors["username"] = "That username or email address was just registered."
            else:
                flash("Your account was created. You can log in now.", "success")
                return redirect(url_for("auth.login"))
    return render_template("register.html", form=form, errors=errors), 400 if errors else 200


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("auth.account"))
    if request.method == "GET":
        return render_template("login.html")

    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "")
    db = get_db()
    ip = _client_ip()
    throttle.purge(db)
    sessions.purge_expired(
        db, current_app.config["SESSION_IDLE_SECONDS"], current_app.config["SESSION_MAX_SECONDS"]
    )

    user = _find_user(db, identifier)
    key = throttle.account_key(user, identifier)
    wait = throttle.retry_after(db, key, ip)
    if wait:
        # Refused before the password is even looked at, so a locked-out
        # guesser learns nothing from a correct guess either.
        response = render_template("login.html", error=_too_many(wait), identifier=identifier)
        return response, 429, {"Retry-After": str(wait)}

    if not _password_matches(db, user, password):
        throttle.record_failure(db, key, ip)
        # One message for a wrong name and for a wrong password: the reply
        # must not reveal which accounts exist.
        error = "Wrong username or password."
        return render_template("login.html", error=error, identifier=identifier), 401

    if user["totp_enabled"]:
        session.clear()
        session["pending_2fa"] = {"uid": user["id"], "at": int(time.time())}
        return redirect(url_for("auth.login_2fa"))

    throttle.clear(db, key)
    _start_session(user)
    return redirect(url_for("auth.account"))


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    if g.user:
        return redirect(url_for("auth.account"))
    db = get_db()
    pending = session.get("pending_2fa")
    user = None
    if pending and time.time() - pending["at"] <= PENDING_2FA_SECONDS:
        user = db.execute(
            "SELECT * FROM users WHERE id = ? AND totp_enabled = 1", (pending["uid"],)
        ).fetchone()
    if user is None:
        session.pop("pending_2fa", None)
        if pending:
            flash("That took too long. Log in again.", "error")
        return redirect(url_for("auth.login"))
    if request.method == "GET":
        return render_template("login_2fa.html")

    key = throttle.account_key(user, "")
    ip = _client_ip()
    wait = throttle.retry_after(db, key, ip)
    if wait:
        session.pop("pending_2fa", None)
        flash(_too_many(wait), "error")
        return redirect(url_for("auth.login"))

    code = request.form.get("code", "")
    used_recovery_code = False
    accepted = twofactor.accept_totp(db, user, code)
    if not accepted:
        accepted = used_recovery_code = twofactor.accept_recovery_code(db, user["id"], code)
    if not accepted:
        # Counted in the database, not in the cookie: a cookie-held counter
        # could be reset by sending an older copy of the cookie.
        throttle.record_failure(db, key, ip)
        return render_template("login_2fa.html", error="That code is not valid."), 401

    throttle.clear(db, key)
    _start_session(user)
    if used_recovery_code:
        left = twofactor.recovery_codes_left(db, user["id"])
        flash(f"You used a recovery code. It will not work again; {left} are left.", "info")
    return redirect(url_for("auth.account"))


@bp.post("/logout")
def logout():
    if g.session_token:
        sessions.destroy(get_db(), g.session_token)
    session.clear()
    flash("You are logged out.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/account")
@login_required
def account():
    db = get_db()
    return render_template(
        "account.html",
        sessions=sessions.list_for_user(db, g.user["id"], g.session_token),
        recovery_codes_left=twofactor.recovery_codes_left(db, g.user["id"]),
    )


@bp.post("/sessions/end-others")
@login_required
def end_other_sessions():
    ended = sessions.destroy_others(get_db(), g.user["id"], g.session_token)
    if ended:
        flash(f"Logged out of {ended} other {'session' if ended == 1 else 'sessions'}.", "success")
    else:
        flash("There are no other sessions.", "info")
    return redirect(url_for("auth.account"))


@bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if g.user["totp_enabled"]:
        return redirect(url_for("auth.account"))
    db = get_db()
    user = g.user
    if user["totp_secret"] is None:
        # The secret is kept, not yet in force, until a code proves the
        # authenticator app really has it.
        with db:
            db.execute(
                "UPDATE users SET totp_secret = ?, totp_last_counter = 0 WHERE id = ?",
                (twofactor.new_secret(), user["id"]),
            )
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()

    error = None
    if request.method == "POST":
        error = _reauthenticate(request.form.get("password", ""))
        if error is None:
            if twofactor.accept_totp(db, user, request.form.get("code", "")):
                codes = twofactor.enable(db, user["id"])
                return render_template("recovery_codes.html", codes=codes, just_enabled=True)
            error = "That code is not valid. Check the time on your phone and try the next code."

    secret = user["totp_secret"]
    page = render_template(
        "setup_2fa.html",
        error=error,
        qr=twofactor.qr_data_uri(twofactor.provisioning_uri(secret, user["username"])),
        secret=twofactor.grouped(secret),
    )
    return page, 400 if error else 200


@bp.post("/2fa/disable")
@login_required
def disable_2fa():
    error = _reauthenticate(request.form.get("password", ""))
    if error:
        flash(error, "error")
    else:
        twofactor.disable(get_db(), g.user["id"])
        flash("Two-factor authentication is off.", "success")
    return redirect(url_for("auth.account"))


@bp.post("/2fa/recovery-codes")
@login_required
def new_recovery_codes():
    if not g.user["totp_enabled"]:
        return redirect(url_for("auth.account"))
    error = _reauthenticate(request.form.get("password", ""))
    if error:
        flash(error, "error")
        return redirect(url_for("auth.account"))
    codes = twofactor.replace_recovery_codes(get_db(), g.user["id"])
    return render_template("recovery_codes.html", codes=codes, just_enabled=False)
