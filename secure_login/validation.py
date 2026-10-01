"""Validation of registration input.

Input is checked against what is allowed (an allow-list) and rejected
otherwise. Nothing is "cleaned" and then accepted.
"""

import re

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,32}")
# Deliberately loose: the only real test of an address is sending mail to it.
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

EMAIL_MAX = 254
PASSWORD_MIN = 12
PASSWORD_MAX = 128

# Passwords of 12 characters or more that attackers still try first. A real
# deployment should check a breached-password list instead of a short one.
COMMON_PASSWORDS = frozenset(
    """
    000000000000 111111111111 123123123123 123456789012 1234567890123
    1234567890ab 1234qwerasdf 1q2w3e4r5t6y 1qaz2wsx3edc abc123abc123
    abcdefghijkl admin1234567 administrator administrator1 asdfghjkl123
    asdfghjklqwe baseball1234 changeme1234 correcthorsebatterystaple
    dragon123456 football1234 iloveyou1234 letmein12345 letmeinletmein
    michael12345 monkey123456 p@ssw0rd1234 passw0rd1234 password1234
    password12345 password123! passwordpassword princess1234 q1w2e3r4t5y6
    qazwsxedcrfv qwerty123456 qwertyuiop12 qwertyuiop123 qwertyuiopas
    sunshine1234 superman1234 trustno1trustno1 welcome12345 zaq12wsxcde3
    """.split()
)


def validate_username(username):
    if not USERNAME_RE.fullmatch(username):
        return "Use 3 to 32 letters, digits, dots, hyphens or underscores."
    return None


def validate_email(email):
    if len(email) > EMAIL_MAX or not EMAIL_RE.fullmatch(email):
        return "Enter a valid email address."
    return None


def validate_password(password, username="", email=""):
    if len(password) < PASSWORD_MIN:
        return f"Use at least {PASSWORD_MIN} characters."
    if len(password) > PASSWORD_MAX:
        return f"Use at most {PASSWORD_MAX} characters."
    lowered = password.lower()
    if len(set(lowered)) < 5:
        return "Use more different characters."
    if lowered in COMMON_PASSWORDS:
        return "That password is too common."
    personal = (username.lower(), email.lower().partition("@")[0])
    if any(len(part) >= 3 and part in lowered for part in personal):
        return "Do not use your username or email address in the password."
    return None


def validate_registration(username, email, password, confirm):
    """Return a dict of field name to error message; empty when all is valid."""
    errors = {
        "username": validate_username(username),
        "email": validate_email(email),
        "password": validate_password(password, username, email),
    }
    if errors["password"] is None and password != confirm:
        errors["confirm"] = "The two passwords do not match."
    return {field: message for field, message in errors.items() if message}
