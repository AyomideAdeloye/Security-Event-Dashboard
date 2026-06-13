"""
Startup script for Railway deployment.
Runs schema + migrations, then starts the Flask app with gunicorn.
"""
import os
import subprocess
import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_conn():
    if DATABASE_URL:
        return psycopg2.connect(DATABASE_URL)
    return psycopg2.connect(
        host=os.environ["POSTGRES_HOST"],
        port=os.environ.get("POSTGRES_PORT", 5432),
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
    )


def run_migrations():
    conn = get_conn()
    conn.autocommit = True
    cur = conn.cursor()

    # Core schema
    cur.execute("""
        CREATE TABLE IF NOT EXISTS organisations (
            id                              SERIAL PRIMARY KEY,
            name                            TEXT NOT NULL,
            plan                            TEXT NOT NULL DEFAULT 'free'
                                                CHECK (plan IN ('free','starter','pro')),
            stripe_customer_id              TEXT UNIQUE,
            stripe_subscription_id          TEXT,
            stripe_subscription_item_id     TEXT,
            created_at                      TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            org_id          INTEGER NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
            email           TEXT NOT NULL UNIQUE,
            password_hash   TEXT NOT NULL,
            role            TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin','member')),
            created_at      TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id          SERIAL PRIMARY KEY,
            org_id      INTEGER NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
            key_hash    TEXT NOT NULL UNIQUE,
            label       TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS events (
            id          SERIAL PRIMARY KEY,
            org_id      INTEGER NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
            ip_address  TEXT,
            event_type  TEXT,
            severity    TEXT,
            category    TEXT,
            description TEXT,
            alert_sent  BOOLEAN NOT NULL DEFAULT FALSE,
            ingested_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS usage (
            id          SERIAL PRIMARY KEY,
            org_id      INTEGER NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
            month       DATE NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            UNIQUE (org_id, month)
        );

        CREATE TABLE IF NOT EXISTS alert_settings (
            org_id          INTEGER PRIMARY KEY REFERENCES organisations(id) ON DELETE CASCADE,
            alert_email     TEXT,
            alerts_enabled  BOOLEAN NOT NULL DEFAULT TRUE
        );

        CREATE TABLE IF NOT EXISTS waitlist (
            id         SERIAL PRIMARY KEY,
            email      TEXT NOT NULL UNIQUE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_events_org_id   ON events(org_id);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(org_id, severity);
        CREATE INDEX IF NOT EXISTS idx_usage_org_month ON usage(org_id, month);
    """)

    cur.close()
    conn.close()
    print("✓ Database schema ready")


if __name__ == "__main__":
    run_migrations()
    port = os.environ.get("PORT", "5000")
    subprocess.run([
        "gunicorn", "app:app",
        "--bind", f"0.0.0.0:{port}",
        "--workers", "2",
        "--timeout", "120",
        "--limit-request-line", "0",
        "--limit-request-field_size", "0",
    ])