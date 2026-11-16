-- logsentinel schema
CREATE TABLE IF NOT EXISTS auth_events (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,          -- ISO-8601
    host        TEXT,
    service     TEXT,
    event       TEXT NOT NULL,          -- FAILED | ACCEPTED | INVALID_USER | SUDO | DISCONNECT
    username    TEXT,
    src_ip      TEXT,
    method      TEXT,                   -- password | publickey
    raw         TEXT
);
CREATE TABLE IF NOT EXISTS web_requests (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    method      TEXT,
    path        TEXT,
    status      INTEGER,
    bytes       INTEGER,
    user_agent  TEXT,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_web_ip  ON web_requests(src_ip, ts);
