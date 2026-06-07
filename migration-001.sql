-- =============================================================
-- Migration 001 — Stripe + email alert support
-- Run this once against your existing database:
--   docker compose exec db psql -U logsentry_user -d logsentry -f /migration_001.sql
-- =============================================================

-- Track whether an alert email has been sent for each high-severity event
ALTER TABLE events
    ADD COLUMN IF NOT EXISTS alert_sent BOOLEAN NOT NULL DEFAULT FALSE;

-- Store Stripe subscription item ID per org (needed for usage reporting)
ALTER TABLE organisations
    ADD COLUMN IF NOT EXISTS stripe_subscription_item_id TEXT;

-- Alert preferences per org
CREATE TABLE IF NOT EXISTS alert_settings (
    org_id          INTEGER PRIMARY KEY REFERENCES organisations(id) ON DELETE CASCADE,
    alert_email     TEXT,           -- where to send alerts (defaults to admin email)
    alerts_enabled  BOOLEAN NOT NULL DEFAULT TRUE
);