-- =============================================================
-- Migration 002 — Subscription plan tiers
-- Run once against your database:
--   docker compose exec db psql -U logsentry_user -d logsentry -c "ALTER TABLE organisations ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'starter', 'pro')), ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT, ADD COLUMN IF NOT EXISTS stripe_subscription_item_id TEXT;"
-- =============================================================

ALTER TABLE organisations
    ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'free'
        CHECK (plan IN ('free', 'starter', 'pro')),
    ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT,
    ADD COLUMN IF NOT EXISTS stripe_subscription_item_id TEXT;