"""Two-factor authentication: time-based one-time codes (TOTP, RFC 6238)
from an authenticator app, with single-use recovery codes as a fallback.
"""

import hashlib
import hmac
import re
import secrets
import time

import pyotp
import segno

ISSUER = "Secure Login"
STEP_SECONDS = 30
RECOVERY_CODE_COUNT = 10

_TOTP_RE = re.compile(r"\d{6}")
_SEPARATORS_RE = re.compile(r"[\s-]+")


def new_secret():
    return pyotp.random_base32()


def provisioning_uri(secret, username):
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_data_uri(uri):
    """The setup QR code as an image that needs no script and no extra request."""
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=3, dark="#000", light="#fff")


def grouped(secret):
    """A secret split into groups of four, for typing it in by hand."""
    return " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))


def _normalize(code):
    return _SEPARATORS_RE.sub("", code).lower()


def _matching_counter(secret, code, last_counter):
    """The time step a code belongs to, or None if the code is not valid.

    The steps before and after the current one are accepted to allow for
    clocks that are slightly off. Steps up to `last_counter` are refused.
    """
    if not _TOTP_RE.fullmatch(code):
        return None
    totp = pyotp.TOTP(secret)
    current = int(time.time()) // STEP_SECONDS
    for counter in (current, current - 1, current + 1):
        if counter > last_counter and hmac.compare_digest(totp.at(counter * STEP_SECONDS), code):
            return counter
    return None


def accept_totp(db, user, code):
    """Check a code from the authenticator app and use it up.

    A code is accepted once: the step it belongs to is remembered, and that
    step and every earlier one are refused afterwards. Someone who watches a
    code being typed therefore cannot use it again.
    """
    if not user["totp_secret"]:
        return False
    counter = _matching_counter(user["totp_secret"], _normalize(code), user["totp_last_counter"])
    if counter is None:
        return False
    with db:
        cursor = db.execute(
            "UPDATE users SET totp_last_counter = ? WHERE id = ? AND totp_last_counter < ?",
            (counter, user["id"], counter),
        )
    # No row changes if a parallel request used the same code first.
    return cursor.rowcount == 1


def _hash_recovery_code(code):
    # A plain hash is enough here: unlike a password, a recovery code is
    # 64 random bits and cannot be found by guessing.
    return hashlib.sha256(_normalize(code).encode()).hexdigest()


def replace_recovery_codes(db, user_id):
    """Create a fresh set of recovery codes, replacing any earlier set.

    The codes are returned so they can be shown once. Only hashes are stored.
    """
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = secrets.token_hex(8)
        codes.append("-".join(raw[i : i + 4] for i in range(0, 16, 4)))
    with db:
        db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        db.executemany(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
            [(user_id, _hash_recovery_code(code)) for code in codes],
        )
    return codes


def accept_recovery_code(db, user_id, code):
    """Check a recovery code and use it up; each one works a single time."""
    with db:
        cursor = db.execute(
            "UPDATE recovery_codes SET used_at = ?"
            " WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
            (int(time.time()), user_id, _hash_recovery_code(code)),
        )
    return cursor.rowcount == 1


def recovery_codes_left(db, user_id):
    return db.execute(
        "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL", (user_id,)
    ).fetchone()[0]


def enable(db, user_id):
    with db:
        db.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (user_id,))
    return replace_recovery_codes(db, user_id)


def disable(db, user_id):
    with db:
        db.execute(
            "UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_last_counter = 0"
            " WHERE id = ?",
            (user_id,),
        )
        db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
