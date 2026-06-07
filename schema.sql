-- =============================================================
-- LogSentry SaaS Schema
-- =============================================================

-- Organisations (one per customer account)
CREATE TABLE IF NOT EXISTS organisations (
    id                  SERIAL PRIMARY KEY,
    name                TEXT NOT NULL,
    stripe_customer_id  TEXT UNIQUE,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Users (many per org; one org admin on signup)
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    org_id          INTEGER NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- API keys (for programmatic log ingest)
CREATE TABLE IF NOT EXISTS api_keys (
    id          SERIAL PRIMARY KEY,
    org_id      INTEGER NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    key_hash    TEXT NOT NULL UNIQUE,   -- store only the hash, never plaintext
    label       TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Security events (scoped to org)
CREATE TABLE IF NOT EXISTS events (
    id          SERIAL PRIMARY KEY,
    org_id      INTEGER NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    ip_address  TEXT,
    event_type  TEXT,
    severity    TEXT,
    category    TEXT,
    description TEXT,
    ingested_at TIMESTAMPTZ DEFAULT NOW()
);

-- Monthly usage counters (for Stripe metered billing)
CREATE TABLE IF NOT EXISTS usage (
    id          SERIAL PRIMARY KEY,
    org_id      INTEGER NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
    month       DATE NOT NULL,          -- always stored as first day of month
    event_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE (org_id, month)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_events_org_id   ON events(org_id);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(org_id, severity);
CREATE INDEX IF NOT EXISTS idx_usage_org_month ON usage(org_id, month);