CREATE TABLE IF NOT EXISTS targets (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    base_url      TEXT NOT NULL,
    admin_key_enc BLOB NOT NULL,
    log_id        TEXT,
    last_seq      INTEGER NOT NULL DEFAULT -1,
    status        TEXT NOT NULL DEFAULT 'unknown',
    last_error    TEXT,
    created_at    REAL NOT NULL,
    polled_at     REAL
);

-- A derived cache of each target's latest-known state, rebuildable from scratch by re-polling.
-- The signed ledger on each gateway stays the only durable evidence; this never substitutes for it.
CREATE TABLE IF NOT EXISTS target_status (
    target_id         TEXT PRIMARY KEY REFERENCES targets(id),
    size              INTEGER NOT NULL,
    safe_to_ship      INTEGER,
    sealed_at         REAL,
    breach_kinds_json TEXT NOT NULL DEFAULT '[]',
    updated_at        REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL
);

-- Only a digest of a session token is ever stored, the same rule gateway_keys.py follows for
-- bearer keys -- never the token itself.
CREATE TABLE IF NOT EXISTS sessions (
    token_digest TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id),
    expires_at   REAL NOT NULL,
    created_at   REAL NOT NULL
);
