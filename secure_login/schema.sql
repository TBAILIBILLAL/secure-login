CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY,
    username          TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email             TEXT    NOT NULL UNIQUE,
    password_hash     TEXT    NOT NULL,
    totp_secret       TEXT,
    totp_enabled      INTEGER NOT NULL DEFAULT 0,
    totp_last_counter INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
);

-- Only a SHA-256 hash of each session token is stored, so a copy of this
-- table cannot be used to take over the sessions in it.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    ip         TEXT    NOT NULL,
    user_agent TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id        INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT    NOT NULL,
    used_at   INTEGER
);
CREATE INDEX IF NOT EXISTS recovery_codes_user ON recovery_codes (user_id);

-- One row per failed attempt, once for the account and once for the address.
CREATE TABLE IF NOT EXISTS login_failures (
    id    INTEGER PRIMARY KEY,
    scope TEXT    NOT NULL CHECK (scope IN ('account', 'ip')),
    key   TEXT    NOT NULL,
    at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS login_failures_key ON login_failures (scope, key, at);
