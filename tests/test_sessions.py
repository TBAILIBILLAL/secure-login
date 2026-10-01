import hashlib
import unittest

from . import BASE_URL, CSRF_RE, PASSWORD, AppTestCase

COOKIE = "__Host-session"


class AccessTests(AppTestCase):
    def test_account_pages_need_a_login(self):
        for path in ("/account", "/2fa/setup"):
            response = self.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertTrue(response.headers["Location"].endswith("/login"), path)

    def test_account_actions_need_a_login(self):
        for path in ("/sessions/end-others", "/2fa/disable", "/2fa/recovery-codes"):
            response = self.post(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertTrue(response.headers["Location"].endswith("/login"), path)

    def test_logged_in_user_is_sent_past_the_login_page(self):
        self.register()
        self.login()
        for path in ("/", "/login", "/register"):
            response = self.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertTrue(response.headers["Location"].endswith("/account"), path)

    def test_account_page_shows_the_user_and_the_session(self):
        self.register()
        self.login()
        page = self.get("/account").get_data(as_text=True)
        self.assertIn("alice@example.com", page)
        self.assertIn("This one", page)


class CookieTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()

    def session_cookie_header(self, response, name):
        headers = [h for h in response.headers.getlist("Set-Cookie") if h.startswith(name + "=")]
        self.assertEqual(len(headers), 1, response.headers)
        return headers[0]

    def test_cookie_is_locked_down(self):
        attributes = self.session_cookie_header(self.login(), COOKIE).split("; ")[1:]
        self.assertIn("Secure", attributes)
        self.assertIn("HttpOnly", attributes)
        self.assertIn("SameSite=Lax", attributes)
        self.assertIn("Path=/", attributes)
        self.assertFalse([a for a in attributes if a.startswith("Domain")], attributes)
        # No expiry date: the browser drops the cookie when it is closed.
        self.assertFalse([a for a in attributes if a.startswith(("Expires", "Max-Age"))])

    def test_local_mode_works_over_plain_http(self):
        self.app = self.new_app(SESSION_COOKIE_SECURE=False)
        client = self.new_client()
        token = CSRF_RE.search(client.get("/login").get_data(as_text=True)).group(1)
        response = client.post(
            "/login", data={"identifier": "alice", "password": PASSWORD, "csrf_token": token}
        )
        header = self.session_cookie_header(response, "session")
        self.assertNotIn("Secure", header)
        self.assertIn("HttpOnly", header)
        self.assertNotIn("Strict-Transport-Security", response.headers)
        self.assertEqual(client.get("/account").status_code, 200)

    def test_database_holds_only_a_hash_of_the_session_token(self):
        self.login()
        with self.client.session_transaction(base_url=BASE_URL) as session:
            token = session["sid"]
        rows = self.db().execute("SELECT * FROM sessions").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["token_hash"], hashlib.sha256(token.encode()).hexdigest())
        self.assertNotIn(token, [str(value) for value in tuple(rows[0])])

    def test_login_replaces_everything_from_before_the_login(self):
        old_token = self.csrf_token()
        old_cookie = self.client.get_cookie(COOKIE).value
        self.login()
        self.assertNotEqual(self.client.get_cookie(COOKIE).value, old_cookie)
        # A form token handed out before the login is not valid after it.
        response = self.client.post("/logout", data={"csrf_token": old_token}, base_url=BASE_URL)
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.logged_in())


class LogoutTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()
        self.login()

    def test_logout_ends_the_session(self):
        response = self.post("/logout")
        self.assertEqual(response.status_code, 302)
        self.assertFalse(self.logged_in())
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_cookie_copied_before_logout_is_useless_after_it(self):
        thief = self.new_client()
        thief.set_cookie(COOKIE, self.client.get_cookie(COOKIE).value, secure=True)
        self.assertTrue(self.logged_in(thief))
        self.post("/logout")
        self.assertFalse(self.logged_in(thief))

    def test_logout_cannot_be_triggered_by_a_link(self):
        self.assertEqual(self.get("/logout").status_code, 405)
        self.assertTrue(self.logged_in())

    def test_log_out_everywhere_else(self):
        other = self.new_client()
        self.login(client=other)
        response = self.post("/sessions/end-others", follow_redirects=True)
        self.assertIn("Logged out of 1 other session.", response.get_data(as_text=True))
        self.assertTrue(self.logged_in())
        self.assertFalse(self.logged_in(other))


class ExpiryTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()
        self.login()

    def test_session_ends_after_30_minutes_without_use(self):
        self.advance(30 * 60)
        self.assertTrue(self.logged_in())
        self.advance(30 * 60 + 1)
        self.assertFalse(self.logged_in())

    def test_session_ends_after_12_hours_even_when_in_use(self):
        for _ in range(36):
            self.advance(20 * 60)
            self.assertTrue(self.logged_in())
        self.advance(1)
        self.assertFalse(self.logged_in())

    def test_expired_sessions_are_removed_from_the_database(self):
        self.advance(31 * 60)
        self.login("nobody", "wrong-password-0", client=self.new_client())
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)


class CsrfTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()

    def send(self, path, data, client=None):
        return (client or self.client).post(path, data=data, base_url=BASE_URL)

    def test_form_without_token_is_refused(self):
        response = self.send("/login", {"identifier": "alice", "password": PASSWORD})
        self.assertEqual(response.status_code, 400)
        self.assertIn("did not come from this site", response.get_data(as_text=True))
        self.assertFalse(self.logged_in())

    def test_form_with_wrong_token_is_refused(self):
        self.get("/login")
        for token in ("", "guess", self.csrf_token(self.new_client())):
            response = self.send("/register", {"csrf_token": token, "username": "bob"})
            self.assertEqual(response.status_code, 400, token)

    def test_actions_of_a_logged_in_user_need_the_token(self):
        self.login()
        for path in ("/logout", "/sessions/end-others", "/2fa/disable", "/2fa/recovery-codes"):
            self.assertEqual(self.send(path, {}).status_code, 400, path)
        self.assertTrue(self.logged_in())


class HeaderTests(AppTestCase):
    def test_pages_carry_the_security_headers(self):
        headers = self.get("/login").headers
        policy = headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertNotIn("unsafe-inline", policy)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("max-age=", headers["Strict-Transport-Security"])

    def test_error_pages_carry_them_too(self):
        response = self.get("/no-such-page")
        self.assertEqual(response.status_code, 404)
        self.assertIn("Content-Security-Policy", response.headers)

    def test_static_files_may_be_cached(self):
        response = self.get("/static/style.css")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.headers.get("Cache-Control"), "no-store")
        response.close()


if __name__ == "__main__":
    unittest.main()
