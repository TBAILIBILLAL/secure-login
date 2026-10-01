import glob
import unittest

from secure_login import throttle

from . import PASSWORD, AppTestCase


class RegistrationTests(AppTestCase):
    def test_registering_creates_an_account_and_leads_to_login(self):
        response = self.register()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/login"))
        row = self.db().execute("SELECT username, email FROM users").fetchone()
        self.assertEqual(tuple(row), ("alice", "alice@example.com"))

    def test_password_is_stored_only_as_an_argon2id_hash(self):
        self.register()
        stored = self.db().execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertTrue(stored.startswith("$argon2id$"), stored)
        for path in glob.glob(self.database + "*"):
            with open(path, "rb") as f:
                self.assertNotIn(PASSWORD.encode(), f.read(), path)

    def test_invalid_input_is_refused_and_explained(self):
        response = self.post(
            "/register",
            {"username": "a b", "email": "nope", "password": "short", "confirm": "short"},
        )
        self.assertEqual(response.status_code, 400)
        page = response.get_data(as_text=True)
        self.assertIn("Use 3 to 32 letters", page)
        self.assertIn("Enter a valid email address", page)
        self.assertIn("Use at least 12 characters", page)
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_username_cannot_be_registered_twice_in_any_case(self):
        self.register()
        response = self.register(username="ALICE", email="other@example.com")
        self.assertEqual(response.status_code, 400)
        self.assertIn("That username is taken", response.get_data(as_text=True))

    def test_email_cannot_be_registered_twice_in_any_case(self):
        self.register()
        response = self.register(username="bob", email="Alice@Example.com")
        self.assertEqual(response.status_code, 400)
        self.assertIn("already registered", response.get_data(as_text=True))

    def test_text_typed_into_a_form_is_shown_as_text_not_markup(self):
        response = self.post(
            "/register",
            {"username": '"><script>alert(1)</script>', "email": "x", "password": "", "confirm": ""},
        )
        page = response.get_data(as_text=True)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)


class LoginTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()

    def test_login_with_username_or_email(self):
        for identifier in ("alice", "ALICE", "alice@example.com", "Alice@Example.com"):
            client = self.new_client()
            response = self.login(identifier, client=client)
            self.assertEqual(response.status_code, 302, identifier)
            self.assertTrue(self.logged_in(client), identifier)

    def test_wrong_password_is_refused(self):
        response = self.login(password="plum-anchor-violin-43")
        self.assertEqual(response.status_code, 401)
        self.assertFalse(self.logged_in())

    def test_unknown_name_and_wrong_password_get_the_same_answer(self):
        wrong_password = self.login(password="not-the-password")
        unknown_name = self.login("nobody", client=self.new_client())
        self.assertEqual(wrong_password.status_code, unknown_name.status_code)
        message = "Wrong username or password."
        self.assertIn(message, wrong_password.get_data(as_text=True))
        self.assertIn(message, unknown_name.get_data(as_text=True))

    def test_overlong_input_is_refused_without_error(self):
        self.assertEqual(self.login("a" * 5000, "b" * 5000).status_code, 401)

    def test_oversized_request_is_refused(self):
        response = self.post("/login", {"identifier": "alice", "password": "x" * 100_000})
        self.assertEqual(response.status_code, 413)

    def test_password_hash_is_upgraded_at_login_when_cost_was_raised(self):
        before = self.db().execute("SELECT password_hash FROM users").fetchone()[0]
        self.app = self.new_app(ARGON2_PARAMS={"time_cost": 2, "memory_cost": 16, "parallelism": 1})
        self.client = self.new_client()
        self.assertEqual(self.login().status_code, 302)
        after = self.db().execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotEqual(before, after)
        self.assertIn("m=16,t=2,p=1", after)
        self.assertEqual(self.login(client=self.new_client()).status_code, 302)


class SqlInjectionTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()

    def test_injection_strings_do_not_log_in(self):
        for identifier in (
            "' OR '1'='1",
            "' OR 1=1 --",
            "alice' --",
            "alice'/*",
            '" OR ""="',
            "' UNION SELECT * FROM users --",
        ):
            for password in (PASSWORD, "' OR '1'='1"):
                client = self.new_client()
                response = self.login(identifier, password, client=client)
                self.assertIn(response.status_code, (401, 429), identifier)
                self.assertFalse(self.logged_in(client), identifier)

    def test_injection_strings_do_not_change_the_database(self):
        self.login("x'; DROP TABLE users; --", "x'; DELETE FROM users; --")
        self.register(username="x'); DROP TABLE users;--", email="mallory@example.com")
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_quote_in_valid_input_is_stored_as_plain_data(self):
        # An apostrophe is legal in an email address. It must be stored and
        # found again exactly as typed, which only works if it is never
        # treated as part of the SQL.
        email = "o'brien@example.com"
        self.assertEqual(self.register(username="obrien", email=email).status_code, 302)
        stored = self.db().execute("SELECT email FROM users WHERE username = 'obrien'").fetchone()
        self.assertEqual(stored[0], email)
        self.assertEqual(self.login(email).status_code, 302)
        self.assertTrue(self.logged_in())


class ThrottleTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()

    def fail(self, identifier="alice", times=1):
        for _ in range(times):
            response = self.login(identifier, "wrong-password-0", client=self.new_client())
        return response

    def test_account_is_locked_after_repeated_failures(self):
        self.assertEqual(self.fail(times=throttle.ACCOUNT_LIMIT).status_code, 401)
        response = self.login()
        self.assertEqual(response.status_code, 429)
        self.assertIn("Too many failed attempts", response.get_data(as_text=True))
        self.assertEqual(response.headers["Retry-After"], str(throttle.WINDOW_SECONDS))
        self.assertFalse(self.logged_in())

    def test_lock_covers_username_and_email_together(self):
        self.fail("alice", times=3)
        self.fail("alice@example.com", times=2)
        self.assertEqual(self.login().status_code, 429)

    def test_lock_ends_when_the_window_has_passed(self):
        self.fail(times=throttle.ACCOUNT_LIMIT)
        self.advance(throttle.WINDOW_SECONDS - 1)
        self.assertEqual(self.login().status_code, 429)
        self.advance(1)
        self.assertEqual(self.login().status_code, 302)

    def test_successful_login_resets_the_count(self):
        self.fail(times=throttle.ACCOUNT_LIMIT - 1)
        self.assertEqual(self.login(client=self.new_client()).status_code, 302)
        self.assertEqual(self.fail(times=throttle.ACCOUNT_LIMIT - 1).status_code, 401)
        self.assertEqual(self.login().status_code, 302)

    def test_unknown_names_lock_like_real_ones(self):
        self.assertEqual(self.fail("nobody", times=throttle.ACCOUNT_LIMIT).status_code, 401)
        self.assertEqual(self.fail("nobody").status_code, 429)

    def test_one_address_cannot_guess_across_many_accounts(self):
        for n in range(throttle.IP_LIMIT):
            self.assertEqual(self.fail(f"user{n}").status_code, 401)
        self.assertEqual(self.login().status_code, 429)

    def test_failed_names_are_not_stored_readably(self):
        # People type passwords into the username field by mistake.
        self.fail("my-secret-typed-in-the-wrong-box")
        keys = [row[0] for row in self.db().execute("SELECT key FROM login_failures")]
        self.assertTrue(keys)
        self.assertFalse(any("my-secret" in key for key in keys), keys)


if __name__ == "__main__":
    unittest.main()
