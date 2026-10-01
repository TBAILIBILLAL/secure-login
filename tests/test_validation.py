import unittest

from secure_login import validation


class UsernameTests(unittest.TestCase):
    def test_accepts_ordinary_names(self):
        for name in ("alice", "Bob_42", "a.b-c", "x" * 32):
            self.assertIsNone(validation.validate_username(name), name)

    def test_rejects_names_outside_the_allowed_set(self):
        for name in (
            "",
            "ab",
            "x" * 33,
            "has space",
            "alice\n",
            "al<script>",
            "bob@example.com",
            "x' OR '1'='1",
            "Robert'); DROP TABLE users;--",
            "аlice",  # Cyrillic "а", which looks like the Latin letter
        ):
            self.assertIsNotNone(validation.validate_username(name), repr(name))


class EmailTests(unittest.TestCase):
    def test_accepts_ordinary_addresses(self):
        for email in ("a@b.co", "first.last+tag@mail.example.org", "o'brien@example.com"):
            self.assertIsNone(validation.validate_email(email), email)

    def test_rejects_malformed_addresses(self):
        for email in ("", "plain", "@example.com", "a@b", "a b@example.com", "a@b@c.com"):
            self.assertIsNotNone(validation.validate_email(email), repr(email))

    def test_rejects_overlong_addresses(self):
        self.assertIsNotNone(validation.validate_email("a" * 250 + "@b.co"))


class PasswordTests(unittest.TestCase):
    def test_accepts_a_long_passphrase_without_symbol_rules(self):
        self.assertIsNone(validation.validate_password("four quiet words here"))

    def test_rejects_short_passwords(self):
        self.assertIn("at least 12", validation.validate_password("Sh0rt!pass"))

    def test_rejects_overlong_passwords(self):
        self.assertIn("at most 128", validation.validate_password("ab1!" * 33))

    def test_rejects_common_passwords_in_any_case(self):
        self.assertIn("too common", validation.validate_password("Password1234"))

    def test_rejects_passwords_with_few_different_characters(self):
        self.assertIn("different characters", validation.validate_password("abababababab"))

    def test_rejects_passwords_containing_the_username_or_email_name(self):
        self.assertIn("username", validation.validate_password("ALICE-is-my-name", "alice"))
        self.assertIn(
            "username", validation.validate_password("jsmith-loves-tea", "other", "jsmith@example.com")
        )


class RegistrationTests(unittest.TestCase):
    def test_valid_input_has_no_errors(self):
        errors = validation.validate_registration(
            "alice", "alice@example.com", "plum-anchor-violin", "plum-anchor-violin"
        )
        self.assertEqual(errors, {})

    def test_reports_every_invalid_field(self):
        errors = validation.validate_registration("a", "nope", "short", "short")
        self.assertEqual(set(errors), {"username", "email", "password"})

    def test_reports_passwords_that_do_not_match(self):
        errors = validation.validate_registration(
            "alice", "alice@example.com", "plum-anchor-violin", "plum-anchor-violim"
        )
        self.assertEqual(set(errors), {"confirm"})


if __name__ == "__main__":
    unittest.main()
