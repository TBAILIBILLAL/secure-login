"""Shared set-up for the tests: a fresh app, database and clock for every test."""

import re
import tempfile
import unittest
from unittest import mock

import pyotp

from secure_login import create_app
from secure_login.db import connect

PASSWORD = "plum-anchor-violin-42"
BASE_URL = "https://localhost"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
# The cheapest parameters argon2 accepts, to keep the tests quick.
FAST_ARGON2 = {"time_cost": 1, "memory_cost": 8, "parallelism": 1}


class AppTestCase(unittest.TestCase):
    def setUp(self):
        # The tests control the clock, so that timeouts, lockouts and
        # one-time codes can be tested without waiting.
        self.now = 1_800_000_000
        clock = mock.patch("time.time", lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)

        folder = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(folder.cleanup)
        self.database = f"{folder.name}/test.db"
        self.app = self.new_app()
        self.client = self.new_client()

    def new_app(self, **config):
        settings = {
            "TESTING": True,
            "SECRET_KEY": "test-key",
            "DATABASE": self.database,
            "ARGON2_PARAMS": FAST_ARGON2,
        }
        settings.update(config)
        return create_app(settings)

    def new_client(self):
        """A separate browser, with its own cookies."""
        return self.app.test_client()

    def advance(self, seconds):
        self.now += seconds

    def db(self):
        conn = connect(self.database)
        self.addCleanup(conn.close)
        return conn

    def get(self, path, client=None, **kwargs):
        return (client or self.client).get(path, base_url=BASE_URL, **kwargs)

    def csrf_token(self, client=None):
        """The token a browser would find in the page it is looking at."""
        page = self.get("/login", client=client, follow_redirects=True)
        return CSRF_RE.search(page.get_data(as_text=True)).group(1)

    def post(self, path, data=None, client=None, **kwargs):
        """Send a form the way a browser would: with the page's CSRF token."""
        data = {"csrf_token": self.csrf_token(client), **(data or {})}
        return (client or self.client).post(path, data=data, base_url=BASE_URL, **kwargs)

    def register(self, username="alice", email="alice@example.com", password=PASSWORD):
        return self.post(
            "/register",
            {"username": username, "email": email, "password": password, "confirm": password},
        )

    def login(self, identifier="alice", password=PASSWORD, client=None):
        return self.post("/login", {"identifier": identifier, "password": password}, client=client)

    def logged_in(self, client=None):
        return self.get("/account", client=client).status_code == 200

    def totp_code(self, secret, steps=0):
        """The code an authenticator app shows now, or `steps` half-minutes away."""
        return pyotp.TOTP(secret).at(self.now + 30 * steps)

    def enable_2fa(self):
        """Turn two-factor on for the logged-in user; return (secret, recovery codes)."""
        self.get("/2fa/setup")
        secret = self.db().execute("SELECT totp_secret FROM users").fetchone()[0]
        page = self.post("/2fa/setup", {"password": PASSWORD, "code": self.totp_code(secret)})
        self.assertEqual(page.status_code, 200)
        codes = re.findall(r"<li>([0-9a-f-]{19})</li>", page.get_data(as_text=True))
        # A code works once, so the next login needs the app's next code.
        self.advance(30)
        return secret, codes
