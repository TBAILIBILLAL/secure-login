"""Server-side sessions.

The browser holds a random token and the database holds its hash. Because
the session lives on the server, logging out really ends it: a copy of the
cookie taken before the logout stops working.
"""

import hashlib
import secrets
import time

# last_seen is only rewritten when it is at least this stale, so that an
# ordinary page view does not cost a database write.
TOUCH_SECONDS = 60


def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create(db, user_id, ip, user_agent):
    """Start a session and return its token, which goes in the cookie."""
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with db:
        db.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, last_seen, ip, user_agent)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (_hash(token), user_id, now, now, ip, user_agent),
        )
    return token


def load(db, token, idle_seconds, max_seconds):
    """Return the session row for a token, or None if it is unknown or expired."""
    token_hash = _hash(token)
    row = db.execute("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)).fetchone()
    if row is None:
        return None
    now = int(time.time())
    if now - row["last_seen"] > idle_seconds or now - row["created_at"] > max_seconds:
        with db:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return None
    if now - row["last_seen"] >= TOUCH_SECONDS:
        with db:
            db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, token_hash))
    return row


def destroy(db, token):
    with db:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash(token),))


def destroy_others(db, user_id, keep_token):
    """End every session of a user except one; return how many were ended."""
    with db:
        cursor = db.execute(
            "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
            (user_id, _hash(keep_token)),
        )
    return cursor.rowcount


def list_for_user(db, user_id, current_token):
    rows = db.execute(
        "SELECT token_hash, created_at, last_seen, ip, user_agent FROM sessions"
        " WHERE user_id = ? ORDER BY last_seen DESC",
        (user_id,),
    ).fetchall()
    current_hash = _hash(current_token)
    return [
        {
            "created_at": row["created_at"],
            "last_seen": row["last_seen"],
            "ip": row["ip"],
            "user_agent": row["user_agent"],
            "current": row["token_hash"] == current_hash,
        }
        for row in rows
    ]


def purge_expired(db, idle_seconds, max_seconds):
    now = int(time.time())
    with db:
        db.execute(
            "DELETE FROM sessions WHERE last_seen < ? OR created_at < ?",
            (now - idle_seconds, now - max_seconds),
        )
