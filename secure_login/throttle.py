"""Slows down password and code guessing.

Failed attempts are counted per account and per network address over a
sliding window. Once a count reaches its limit, further attempts are refused
until the oldest failures leave the window, whether or not they are correct.
"""

import hashlib
import time

WINDOW_SECONDS = 15 * 60
ACCOUNT_LIMIT = 5
IP_LIMIT = 20


def account_key(user, identifier):
    """The key failures are counted under for a login attempt.

    Unknown names get a key too, so that a name which does not exist locks
    exactly like one which does. The name is hashed because people sometimes
    type their password into the username field, and that must not end up
    readable in the database.
    """
    if user is not None:
        return f"user:{user['id']}"
    return "name:" + hashlib.sha256(identifier.lower().encode()).hexdigest()


def _retry_after(db, scope, key, limit, now):
    rows = db.execute(
        "SELECT at FROM login_failures WHERE scope = ? AND key = ? AND at > ?"
        " ORDER BY at DESC LIMIT ?",
        (scope, key, now - WINDOW_SECONDS, limit),
    ).fetchall()
    if len(rows) < limit:
        return 0
    # Attempts are allowed again when the oldest of the last `limit` failures
    # is no longer inside the window.
    return rows[-1]["at"] + WINDOW_SECONDS - now


def retry_after(db, key, ip):
    """Seconds until another attempt is allowed; 0 if one is allowed now."""
    now = int(time.time())
    return max(
        _retry_after(db, "account", key, ACCOUNT_LIMIT, now),
        _retry_after(db, "ip", ip, IP_LIMIT, now),
    )


def record_failure(db, key, ip):
    now = int(time.time())
    with db:
        db.executemany(
            "INSERT INTO login_failures (scope, key, at) VALUES (?, ?, ?)",
            [("account", key, now), ("ip", ip, now)],
        )


def clear(db, key):
    """Forget an account's failures after a successful login.

    Failures counted against the address are kept: one success must not
    reset the limit for someone guessing many accounts from one address.
    """
    with db:
        db.execute("DELETE FROM login_failures WHERE scope = 'account' AND key = ?", (key,))


def purge(db):
    with db:
        db.execute("DELETE FROM login_failures WHERE at <= ?", (int(time.time()) - WINDOW_SECONDS,))
