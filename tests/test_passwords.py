import re
import unittest

from secure_login.passwords import Passwords

from . import FAST_ARGON2


class PasswordHashingTests(unittest.TestCase):
    def setUp(self):
        self.passwords = Passwords(**FAST_ARGON2)

    def test_default_settings_are_argon2id_at_recommended_cost(self):
        stored = Passwords().hash("plum-anchor-violin")
        match = re.match(r"\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$", stored)
        self.assertIsNotNone(match, stored)
        memory_kib, passes, lanes = map(int, match.groups())
        # RFC 9106's second recommended option: 64 MiB, 3 passes, 4 lanes.
        self.assertGreaterEqual(memory_kib, 64 * 1024)
        self.assertGreaterEqual(passes, 3)
        self.assertGreaterEqual(lanes, 1)

    def test_hash_does_not_contain_the_password(self):
        self.assertNotIn("plum-anchor-violin", self.passwords.hash("plum-anchor-violin"))

    def test_same_password_hashes_differently_each_time(self):
        first = self.passwords.hash("plum-anchor-violin")
        second = self.passwords.hash("plum-anchor-violin")
        self.assertNotEqual(first, second)

    def test_verify_accepts_only_the_right_password(self):
        stored = self.passwords.hash("plum-anchor-violin")
        self.assertTrue(self.passwords.verify(stored, "plum-anchor-violin"))
        self.assertFalse(self.passwords.verify(stored, "plum-anchor-violim"))
        self.assertFalse(self.passwords.verify(stored, ""))

    def test_verify_refuses_a_value_that_is_not_a_hash(self):
        self.assertFalse(self.passwords.verify("plum-anchor-violin", "plum-anchor-violin"))
        self.assertFalse(self.passwords.verify("", "plum-anchor-violin"))

    def test_same_text_typed_with_different_code_points_matches(self):
        composed = "café-anchor-violin"
        decomposed = "café-anchor-violin"
        self.assertTrue(self.passwords.verify(self.passwords.hash(composed), decomposed))

    def test_needs_rehash_when_cost_was_raised(self):
        stored = self.passwords.hash("plum-anchor-violin")
        self.assertFalse(self.passwords.needs_rehash(stored))
        stronger = Passwords(**{**FAST_ARGON2, "time_cost": 2})
        self.assertTrue(stronger.needs_rehash(stored))


if __name__ == "__main__":
    unittest.main()
