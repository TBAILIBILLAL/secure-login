"""Password hashing with Argon2id."""

import secrets
import unicodedata

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError


def _normalize(password):
    # The same characters can be typed as different code points depending on
    # the keyboard; normalizing keeps the password usable on every device.
    return unicodedata.normalize("NFKC", password)


class Passwords:
    """Hashes and verifies passwords.

    Each hash carries its own random salt and its cost parameters, so the
    parameters can be raised later and old hashes upgraded at the next login.
    """

    def __init__(self, **params):
        # argon2-cffi's defaults are Argon2id with the RFC 9106 low-memory
        # profile (64 MiB, 3 passes, 4 lanes).
        self._hasher = PasswordHasher(**params)
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(16))

    def hash(self, password):
        return self._hasher.hash(_normalize(password))

    def verify(self, stored_hash, password):
        try:
            return self._hasher.verify(stored_hash, _normalize(password))
        except (VerificationError, InvalidHashError):
            return False

    def verify_dummy(self, password):
        """Spend the time of a real check when there is no account to check.

        Without this, a login for an unknown name would answer faster than
        one for a known name, and the difference would reveal which names
        are registered.
        """
        self.verify(self._dummy_hash, password)

    def needs_rehash(self, stored_hash):
        return self._hasher.check_needs_rehash(stored_hash)
