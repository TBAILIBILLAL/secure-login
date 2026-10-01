import unittest

from secure_login import throttle

from . import PASSWORD, AppTestCase


class SetupTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()
        self.login()

    def user(self):
        return self.db().execute("SELECT * FROM users").fetchone()

    def test_setup_page_shows_a_qr_code_and_the_key(self):
        page = self.get("/2fa/setup").get_data(as_text=True)
        secret = self.user()["totp_secret"]
        self.assertIn('src="data:image/svg+xml', page)
        self.assertIn(" ".join(secret[i : i + 4] for i in range(0, len(secret), 4)), page)
        self.assertEqual(len(secret), 32)  # 160 bits in base32

    def test_key_stays_the_same_until_setup_is_finished(self):
        self.get("/2fa/setup")
        first = self.user()["totp_secret"]
        self.get("/2fa/setup")
        self.assertEqual(self.user()["totp_secret"], first)

    def test_wrong_code_does_not_turn_it_on(self):
        self.get("/2fa/setup")
        response = self.post("/2fa/setup", {"password": PASSWORD, "code": "000000"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.user()["totp_enabled"], 0)

    def test_wrong_password_does_not_turn_it_on(self):
        self.get("/2fa/setup")
        code = self.totp_code(self.user()["totp_secret"])
        response = self.post("/2fa/setup", {"password": "not-the-password", "code": code})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.user()["totp_enabled"], 0)

    def test_right_code_turns_it_on_and_shows_recovery_codes_once(self):
        secret, codes = self.enable_2fa()
        self.assertEqual(self.user()["totp_enabled"], 1)
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)
        stored = [row[0] for row in self.db().execute("SELECT code_hash FROM recovery_codes")]
        self.assertEqual(len(stored), 10)
        self.assertFalse(set(stored) & set(codes), "recovery codes must be stored hashed")
        account = self.get("/account").get_data(as_text=True)
        self.assertFalse([code for code in codes if code in account])
        self.assertNotIn(secret, account)


class LoginTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()
        self.login()
        self.secret, self.recovery_codes = self.enable_2fa()
        self.post("/logout")

    def enter(self, code):
        return self.post("/login/2fa", {"code": code})

    def test_password_alone_is_not_enough(self):
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/login/2fa"))
        self.assertFalse(self.logged_in())
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_code_step_cannot_be_reached_without_the_password(self):
        response = self.get("/login/2fa")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.enter(self.totp_code(self.secret)).status_code, 302)
        self.assertFalse(self.logged_in())

    def test_right_code_logs_in(self):
        self.login()
        self.assertEqual(self.enter(self.totp_code(self.secret)).status_code, 302)
        self.assertTrue(self.logged_in())

    def test_code_may_be_typed_with_a_space(self):
        self.login()
        code = self.totp_code(self.secret)
        self.assertEqual(self.enter(f" {code[:3]} {code[3:]} ").status_code, 302)
        self.assertTrue(self.logged_in())

    def test_wrong_code_is_refused(self):
        self.login()
        code = self.totp_code(self.secret)
        wrong = f"{(int(code) + 1) % 1_000_000:06d}"
        self.assertEqual(self.enter(wrong).status_code, 401)
        self.assertFalse(self.logged_in())

    def test_code_works_only_once(self):
        code = self.totp_code(self.secret)
        self.login()
        self.enter(code)
        self.assertTrue(self.logged_in())
        self.post("/logout")

        self.login()
        self.assertEqual(self.enter(code).status_code, 401)
        self.assertFalse(self.logged_in())

        self.advance(30)
        self.assertEqual(self.enter(self.totp_code(self.secret)).status_code, 302)
        self.assertTrue(self.logged_in())

    def test_small_clock_differences_are_tolerated(self):
        self.login()
        self.assertEqual(self.enter(self.totp_code(self.secret, steps=1)).status_code, 302)
        self.assertTrue(self.logged_in())

    def test_old_codes_are_refused(self):
        self.advance(120)
        self.login()
        self.assertEqual(self.enter(self.totp_code(self.secret, steps=-2)).status_code, 401)
        self.assertFalse(self.logged_in())

    def test_code_step_must_follow_the_password_within_five_minutes(self):
        self.login()
        self.advance(5 * 60 + 1)
        response = self.enter(self.totp_code(self.secret))
        self.assertTrue(response.headers["Location"].endswith("/login"))
        self.assertFalse(self.logged_in())

    def test_code_guessing_locks_the_account(self):
        self.login()
        for _ in range(throttle.ACCOUNT_LIMIT):
            self.assertEqual(self.enter("000000").status_code, 401)
        response = self.enter(self.totp_code(self.secret))
        self.assertTrue(response.headers["Location"].endswith("/login"))
        self.assertFalse(self.logged_in())
        self.assertEqual(self.login().status_code, 429)

    def test_recovery_code_logs_in_once(self):
        code = self.recovery_codes[0]
        self.login()
        response = self.post("/login/2fa", {"code": code}, follow_redirects=True)
        self.assertIn("9 are left", response.get_data(as_text=True))
        self.assertTrue(self.logged_in())
        self.post("/logout")

        self.login()
        self.assertEqual(self.enter(code).status_code, 401)
        self.assertFalse(self.logged_in())

    def test_recovery_code_may_be_typed_loosely(self):
        self.login()
        typed = self.recovery_codes[3].replace("-", " ").upper()
        self.assertEqual(self.enter(typed).status_code, 302)
        self.assertTrue(self.logged_in())


class ManageTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register()
        self.login()
        self.secret, self.recovery_codes = self.enable_2fa()

    def enabled(self):
        return self.db().execute("SELECT totp_enabled FROM users").fetchone()[0]

    def test_turning_it_off_needs_the_password(self):
        self.post("/2fa/disable", {"password": "not-the-password"})
        self.assertEqual(self.enabled(), 1)

    def test_turning_it_off_removes_the_key_and_the_recovery_codes(self):
        self.post("/2fa/disable", {"password": PASSWORD})
        user = self.db().execute("SELECT * FROM users").fetchone()
        self.assertEqual(user["totp_enabled"], 0)
        self.assertIsNone(user["totp_secret"])
        self.assertEqual(self.db().execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0], 0)
        self.post("/logout")
        self.login()
        self.assertTrue(self.logged_in())

    def test_new_recovery_codes_need_the_password(self):
        before = self.db().execute("SELECT code_hash FROM recovery_codes").fetchall()
        self.post("/2fa/recovery-codes", {"password": "not-the-password"})
        after = self.db().execute("SELECT code_hash FROM recovery_codes").fetchall()
        self.assertEqual([tuple(r) for r in before], [tuple(r) for r in after])

    def test_new_recovery_codes_replace_the_old_ones(self):
        page = self.post("/2fa/recovery-codes", {"password": PASSWORD}).get_data(as_text=True)
        self.assertNotIn(self.recovery_codes[0], page)
        self.post("/logout")
        self.login()
        self.assertEqual(self.post("/login/2fa", {"code": self.recovery_codes[0]}).status_code, 401)
        self.assertFalse(self.logged_in())

    def test_setup_page_is_closed_once_it_is_on(self):
        response = self.get("/2fa/setup")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/account"))


if __name__ == "__main__":
    unittest.main()
