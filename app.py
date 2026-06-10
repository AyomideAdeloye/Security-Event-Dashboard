import os
import secrets
import hashlib
from datetime import date
from functools import wraps

import bcrypt
import psycopg2
import psycopg2.extras
import stripe
import resend
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort, g, jsonify
)
from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user, login_required, current_user
)
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# ---------------------------------------------------------------------------
# Plan definitions — single source of truth
# ---------------------------------------------------------------------------

PLANS = {
    "free": {
        "name":        "Free",
        "price":       0,
        "event_limit": 500,          # None = unlimited
        "stripe_price_id": None,
    },
    "starter": {
        "name":        "Starter",
        "price":       29,
        "event_limit": 50_000,
        "stripe_price_id": os.environ.get("STRIPE_STARTER_PRICE_ID", ""),
    },
    "pro": {
        "name":        "Pro",
        "price":       79,
        "event_limit": None,         # unlimited
        "stripe_price_id": os.environ.get("STRIPE_PRO_PRICE_ID", ""),
    },
}

EVENTS_PER_PAGE    = 50
MAX_FILE_SIZE      = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".log", ".txt"}

stripe.api_key        = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

resend.api_key   = os.environ.get("RESEND_API_KEY", "")
ALERT_FROM_EMAIL = os.environ.get("ALERT_FROM_EMAIL", "alerts@logsentry.io")

# ---------------------------------------------------------------------------
# Flask-Login
# ---------------------------------------------------------------------------

login_manager = LoginManager(app)
login_manager.login_view    = "login"
login_manager.login_message = "Please log in to access the dashboard."


class User(UserMixin):
    def __init__(self, id, org_id, email, role):
        self.id     = id
        self.org_id = org_id
        self.email  = email
        self.role   = role

    @property
    def is_admin(self):
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id):
    db  = get_db()
    row = query_one(db, "SELECT * FROM users WHERE id = %s", (user_id,))
    if not row:
        return None
    return User(row["id"], row["org_id"], row["email"], row["role"])


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        database_url = os.environ.get("DATABASE_URL")
        if database_url:
            g.db = psycopg2.connect(database_url,
                cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            g.db = psycopg2.connect(
                host=os.environ["POSTGRES_HOST"],
                port=os.environ.get("POSTGRES_PORT", 5432),
                dbname=os.environ["POSTGRES_DB"],
                user=os.environ["POSTGRES_USER"],
                password=os.environ["POSTGRES_PASSWORD"],
                cursor_factory=psycopg2.extras.RealDictCursor,
            )
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_one(db, sql, params=()):
    with db.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def query_all(db, sql, params=()):
    with db.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def execute(db, sql, params=()):
    with db.cursor() as cur:
        cur.execute(sql, params)
    db.commit()

# ---------------------------------------------------------------------------
# Plan / usage helpers
# ---------------------------------------------------------------------------

def current_month():
    return date.today().replace(day=1)


def get_org(db, org_id):
    return query_one(db, "SELECT * FROM organisations WHERE id = %s", (org_id,))


def get_plan(org):
    """Return plan dict for an org row."""
    return PLANS.get(org["plan"], PLANS["free"])


def get_event_limit(org):
    """Return integer limit or None for unlimited."""
    return get_plan(org)["event_limit"]


def get_usage(db, org_id):
    row = query_one(
        db,
        "SELECT event_count FROM usage WHERE org_id = %s AND month = %s",
        (org_id, current_month()),
    )
    return row["event_count"] if row else 0


def increment_usage(db, org_id, count):
    execute(db, """
        INSERT INTO usage (org_id, month, event_count)
        VALUES (%s, %s, %s)
        ON CONFLICT (org_id, month)
        DO UPDATE SET event_count = usage.event_count + EXCLUDED.event_count
    """, (org_id, current_month(), count))


def is_over_limit(db, org_id):
    org   = get_org(db, org_id)
    limit = get_event_limit(org)
    if limit is None:
        return False          # Pro — unlimited
    return get_usage(db, org_id) >= limit


def remaining_events(db, org_id):
    """How many events can still be ingested this month. None = unlimited."""
    org   = get_org(db, org_id)
    limit = get_event_limit(org)
    if limit is None:
        return None
    return max(0, limit - get_usage(db, org_id))

# ---------------------------------------------------------------------------
# Stripe helpers
# ---------------------------------------------------------------------------

def get_or_create_stripe_customer(db, org):
    if org.get("stripe_customer_id"):
        return org["stripe_customer_id"]
    admin = query_one(db,
        "SELECT email FROM users WHERE org_id = %s AND role = 'admin' LIMIT 1",
        (org["id"],))
    customer = stripe.Customer.create(
        email=admin["email"] if admin else None,
        name=org["name"],
    )
    execute(db,
        "UPDATE organisations SET stripe_customer_id = %s WHERE id = %s",
        (customer.id, org["id"]))
    return customer.id


def create_checkout_session(db, org_id, plan_key):
    """Create a Stripe Checkout session for upgrading to a paid plan."""
    plan = PLANS[plan_key]
    if not plan["stripe_price_id"]:
        return None
    org         = get_org(db, org_id)
    customer_id = get_or_create_stripe_customer(db, org)
    session     = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": plan["stripe_price_id"], "quantity": 1}],
        mode="subscription",
        success_url=url_for("settings", _external=True) + "?upgraded=1",
        cancel_url=url_for("settings", _external=True),
        metadata={"org_id": org_id, "plan": plan_key},
    )
    return session.url

# ---------------------------------------------------------------------------
# Email alerts
# ---------------------------------------------------------------------------

def send_high_severity_alert(to_email, org_name, event):
    if not resend.api_key:
        return
    try:
        resend.Emails.send({
            "from": ALERT_FROM_EMAIL,
            "to":   [to_email],
            "subject": f"[LogSentry] High severity alert — {event['event_type']}",
            "html": f"""
                <div style="font-family:monospace;background:#0d0f12;color:#e8eaf0;padding:24px;border-radius:8px;">
                    <h2 style="color:#f05252;margin-top:0;">⚠ High Severity Alert</h2>
                    <p style="color:#6b7280;">Organisation: <strong style="color:#e8eaf0;">{org_name}</strong></p>
                    <table style="width:100%;border-collapse:collapse;margin-top:16px;">
                        <tr><td style="color:#6b7280;padding:6px 0;">Event type</td><td style="color:#e8eaf0;">{event['event_type']}</td></tr>
                        <tr><td style="color:#6b7280;padding:6px 0;">IP address</td><td style="color:#e8eaf0;">{event['ip_address']}</td></tr>
                        <tr><td style="color:#6b7280;padding:6px 0;">Category</td><td style="color:#e8eaf0;">{event['category']}</td></tr>
                        <tr><td style="color:#6b7280;padding:6px 0;">Description</td><td style="color:#e8eaf0;">{event['description']}</td></tr>
                    </table>
                    <p style="margin-top:24px;"><a href="https://logsentry.io/alerts" style="color:#60a5fa;">View all alerts →</a></p>
                </div>
            """,
        })
    except Exception as e:
        app.logger.error(f"Resend alert failed: {e}")


def process_alerts(db, org_id, inserted_ids):
    if not inserted_ids:
        return
    settings = query_one(db, "SELECT * FROM alert_settings WHERE org_id = %s", (org_id,))
    if settings and not settings["alerts_enabled"]:
        return
    alert_email = settings["alert_email"] if settings else None
    if not alert_email:
        admin = query_one(db,
            "SELECT email FROM users WHERE org_id = %s AND role = 'admin' LIMIT 1",
            (org_id,))
        alert_email = admin["email"] if admin else None
    if not alert_email:
        return
    org        = get_org(db, org_id)
    high_evts  = query_all(db, """
        SELECT * FROM events
        WHERE id = ANY(%s) AND severity = 'High' AND alert_sent = FALSE
    """, (list(inserted_ids),))
    for evt in high_evts:
        send_high_severity_alert(alert_email, org["name"], evt)
        execute(db, "UPDATE events SET alert_sent = TRUE WHERE id = %s", (evt["id"],))

# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

def classify_event(line: str):
    line = line.strip()
    if not line:
        return None
    parts      = line.split()
    ip_address = parts[0] if parts else "Unknown"
    if "FAILED_LOGIN" in line:
        return ip_address, "FAILED_LOGIN", "High",   "Authentication", "Possible brute force or unauthorized login attempt"
    elif "PORT_SCAN" in line:
        return ip_address, "PORT_SCAN",   "High",   "Network",        "Possible network reconnaissance activity"
    elif "AUTH_SUCCESS" in line:
        return ip_address, "AUTH_SUCCESS","Low",    "Authentication", "Successful login event"
    elif "ERROR" in line:
        return ip_address, "ERROR",       "Medium", "System",         "System error detected"
    elif "WARNING" in line:
        return ip_address, "WARNING",     "Medium", "System",         "Warning event detected"
    else:
        return ip_address, "UNKNOWN",     "Low",    "Uncategorized",  "Unclassified security event"

# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        org_name = request.form.get("org_name", "").strip()
        email    = request.form.get("email",    "").strip().lower()
        password = request.form.get("password", "")
        if not org_name or not email or not password:
            flash("All fields are required.", "error")
            return render_template("signup.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("signup.html")
        db = get_db()
        if query_one(db, "SELECT id FROM users WHERE email = %s", (email,)):
            flash("An account with that email already exists.", "error")
            return render_template("signup.html")
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO organisations (name, plan) VALUES (%s, 'free') RETURNING id",
                (org_name,))
            org_id = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO users (org_id, email, password_hash, role) VALUES (%s, %s, %s, 'admin') RETURNING id",
                (org_id, email, pw_hash))
            user_id = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO alert_settings (org_id, alert_email, alerts_enabled) VALUES (%s, %s, TRUE)",
                (org_id, email))
        db.commit()
        if stripe.api_key:
            try:
                org = get_org(db, org_id)
                get_or_create_stripe_customer(db, org)
            except Exception as e:
                app.logger.error(f"Stripe customer creation failed: {e}")
        login_user(User(user_id, org_id, email, "admin"))
        flash("Welcome to LogSentry!", "success")
        return redirect(url_for("index"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        email    = request.form.get("email",    "").strip().lower()
        password = request.form.get("password", "")
        db  = get_db()
        row = query_one(db, "SELECT * FROM users WHERE email = %s", (email,))
        if row and bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
            login_user(User(row["id"], row["org_id"], row["email"], row["role"]))
            return redirect(request.args.get("next") or url_for("index"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# Dashboard routes
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    db     = get_db()
    org_id = current_user.org_id
    org    = get_org(db, org_id)
    plan   = get_plan(org)
    limit  = get_event_limit(org)
    usage  = get_usage(db, org_id)

    total_events  = query_one(db, "SELECT COUNT(*) AS n FROM events WHERE org_id = %s", (org_id,))["n"]
    high_events   = query_one(db, "SELECT COUNT(*) AS n FROM events WHERE org_id = %s AND severity='High'", (org_id,))["n"]
    failed_logins = query_one(db, "SELECT COUNT(*) AS n FROM events WHERE org_id = %s AND event_type='FAILED_LOGIN'", (org_id,))["n"]
    port_scans    = query_one(db, "SELECT COUNT(*) AS n FROM events WHERE org_id = %s AND event_type='PORT_SCAN'", (org_id,))["n"]

    return render_template("index.html",
        total_events=total_events,
        high_events=high_events,
        failed_logins=failed_logins,
        port_scans=port_scans,
        usage_count=usage,
        free_tier_limit=limit,
        over_limit=(limit is not None and usage >= limit),
        plan=plan,
        org=org,
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload_logs():
    db     = get_db()
    org_id = current_user.org_id

    if is_over_limit(db, org_id):
        org  = get_org(db, org_id)
        plan = get_plan(org)
        flash(f"Monthly limit of {plan['event_limit']:,} events reached. Upgrade your plan to continue.", "error")
        return redirect(url_for("index"))

    log_file = request.files.get("log_file")
    if not log_file or not log_file.filename:
        abort(400, "No file provided.")
    _, ext = os.path.splitext(log_file.filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        abort(400, f"Invalid file type '{ext}'.")
    raw = log_file.read(MAX_FILE_SIZE + 1)
    if len(raw) > MAX_FILE_SIZE:
        abort(413, "File exceeds the 5 MB limit.")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        abort(400, "File must be UTF-8 encoded text.")

    rem          = remaining_events(db, org_id)   # None = unlimited
    inserted     = 0
    inserted_ids = []
    hit_limit    = False

    with db.cursor() as cur:
        for line in lines:
            if rem is not None and inserted >= rem:
                hit_limit = True
                break
            result = classify_event(line)
            if result is None:
                continue
            ip, event_type, severity, category, description = result
            cur.execute("""
                INSERT INTO events (org_id, ip_address, event_type, severity, category, description)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (org_id, ip, event_type, severity, category, description))
            inserted_ids.append(cur.fetchone()["id"])
            inserted += 1
    db.commit()

    if inserted > 0:
        increment_usage(db, org_id, inserted)
        process_alerts(db, org_id, inserted_ids)

    if hit_limit:
        flash(f"Plan limit reached mid-upload. {inserted:,} events ingested. Upgrade for more.", "warning")

    return redirect(url_for("events", uploaded=inserted))


@app.route("/events")
@login_required
def events():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    offset     = (page - 1) * EVENTS_PER_PAGE
    db         = get_db()
    org_id     = current_user.org_id
    total      = query_one(db, "SELECT COUNT(*) AS n FROM events WHERE org_id = %s", (org_id,))["n"]
    event_rows = query_all(db,
        "SELECT * FROM events WHERE org_id = %s ORDER BY id DESC LIMIT %s OFFSET %s",
        (org_id, EVENTS_PER_PAGE, offset))
    total_pages = max(1, (total + EVENTS_PER_PAGE - 1) // EVENTS_PER_PAGE)
    return render_template("events.html",
        event_rows=event_rows, page=page,
        total_pages=total_pages, total=total,
        uploaded=request.args.get("uploaded"))


@app.route("/alerts")
@login_required
def alerts():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    offset     = (page - 1) * EVENTS_PER_PAGE
    db         = get_db()
    org_id     = current_user.org_id
    total      = query_one(db, "SELECT COUNT(*) AS n FROM events WHERE org_id = %s AND severity='High'", (org_id,))["n"]
    alert_rows = query_all(db,
        "SELECT * FROM events WHERE org_id = %s AND severity='High' ORDER BY id DESC LIMIT %s OFFSET %s",
        (org_id, EVENTS_PER_PAGE, offset))
    total_pages = max(1, (total + EVENTS_PER_PAGE - 1) // EVENTS_PER_PAGE)
    return render_template("alerts.html",
        alert_rows=alert_rows, page=page,
        total_pages=total_pages, total=total)


@app.route("/events/clear", methods=["POST"])
@login_required
@admin_required
def clear_events():
    db = get_db()
    execute(db, "DELETE FROM events WHERE org_id = %s", (current_user.org_id,))
    return redirect(url_for("index"))

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@app.route("/settings")
@login_required
@admin_required
def settings():
    db   = get_db()
    org  = get_org(db, current_user.org_id)
    plan = get_plan(org)
    keys = query_all(db,
        "SELECT id, label, created_at FROM api_keys WHERE org_id = %s ORDER BY created_at DESC",
        (current_user.org_id,))
    alert_settings = query_one(db,
        "SELECT * FROM alert_settings WHERE org_id = %s", (current_user.org_id,))
    usage = get_usage(db, current_user.org_id)
    upgraded = request.args.get("upgraded")
    if upgraded:
        flash("Plan upgraded successfully! Welcome to your new plan.", "success")
    return render_template("settings.html",
        api_keys=keys,
        alert_settings=alert_settings,
        usage_count=usage,
        org=org,
        plan=plan,
        plans=PLANS)


@app.route("/settings/alerts", methods=["POST"])
@login_required
@admin_required
def update_alert_settings():
    db             = get_db()
    alert_email    = request.form.get("alert_email", "").strip()
    alerts_enabled = request.form.get("alerts_enabled") == "on"
    execute(db, """
        INSERT INTO alert_settings (org_id, alert_email, alerts_enabled)
        VALUES (%s, %s, %s)
        ON CONFLICT (org_id)
        DO UPDATE SET alert_email = EXCLUDED.alert_email,
                      alerts_enabled = EXCLUDED.alerts_enabled
    """, (current_user.org_id, alert_email or None, alerts_enabled))
    flash("Alert settings saved.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/api-key/create", methods=["POST"])
@login_required
@admin_required
def create_api_key():
    label     = request.form.get("label", "").strip() or "Unnamed key"
    plaintext = secrets.token_urlsafe(32)
    key_hash  = hashlib.sha256(plaintext.encode()).hexdigest()
    db        = get_db()
    execute(db,
        "INSERT INTO api_keys (org_id, key_hash, label) VALUES (%s, %s, %s)",
        (current_user.org_id, key_hash, label))
    flash(f"api_key_created:{plaintext}", "api_key")
    return redirect(url_for("settings"))


@app.route("/settings/api-key/<int:key_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_api_key(key_id):
    db = get_db()
    execute(db,
        "DELETE FROM api_keys WHERE id = %s AND org_id = %s",
        (key_id, current_user.org_id))
    return redirect(url_for("settings"))

# ---------------------------------------------------------------------------
# Billing / Stripe Checkout
# ---------------------------------------------------------------------------

@app.route("/billing/upgrade/<plan_key>")
@login_required
@admin_required
def upgrade(plan_key):
    if plan_key not in ("starter", "pro"):
        abort(400)
    db  = get_db()
    url = create_checkout_session(db, current_user.org_id, plan_key)
    if not url:
        flash("Stripe is not configured yet. Add your price IDs to .env.", "error")
        return redirect(url_for("settings"))
    return redirect(url)


@app.route("/billing/portal")
@login_required
@admin_required
def billing_portal():
    db  = get_db()
    org = get_org(db, current_user.org_id)
    if not org or not org.get("stripe_customer_id"):
        flash("No billing account found. Contact support.", "error")
        return redirect(url_for("settings"))
    session = stripe.billing_portal.Session.create(
        customer=org["stripe_customer_id"],
        return_url=url_for("settings", _external=True),
    )
    return redirect(session.url)


@app.route("/billing/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig     = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.SignatureVerificationError):
        abort(400)

    obj = event["data"]["object"]

    if event["type"] == "checkout.session.completed":
        org_id   = int(obj["metadata"].get("org_id", 0))
        plan_key = obj["metadata"].get("plan", "free")
        sub_id   = obj.get("subscription")
        if org_id and plan_key in PLANS:
            db = get_db()
            execute(db,
                "UPDATE organisations SET plan = %s, stripe_subscription_id = %s WHERE id = %s",
                (plan_key, sub_id, org_id))
            # Fetch subscription item ID for future usage reporting
            if sub_id:
                sub  = stripe.Subscription.retrieve(sub_id)
                item = sub["items"]["data"][0]
                execute(db,
                    "UPDATE organisations SET stripe_subscription_item_id = %s WHERE id = %s",
                    (item["id"], org_id))

    elif event["type"] == "customer.subscription.deleted":
        customer_id = obj.get("customer")
        if customer_id:
            db = get_db()
            execute(db,
                "UPDATE organisations SET plan = 'free', stripe_subscription_id = NULL, stripe_subscription_item_id = NULL WHERE stripe_customer_id = %s",
                (customer_id,))

    return jsonify(success=True)

# ---------------------------------------------------------------------------
# API ingest
# ---------------------------------------------------------------------------

@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401, "Missing or invalid Authorization header.")
    key_hash = hashlib.sha256(auth.removeprefix("Bearer ").strip().encode()).hexdigest()
    db  = get_db()
    row = query_one(db, "SELECT org_id FROM api_keys WHERE key_hash = %s", (key_hash,))
    if not row:
        abort(401, "Invalid API key.")
    org_id = row["org_id"]
    if is_over_limit(db, org_id):
        return {"error": "Monthly event limit reached. Upgrade your plan."}, 429
    data  = request.get_json(silent=True)
    lines = data.get("lines", []) if data else []
    if not isinstance(lines, list):
        abort(400, "Body must be JSON with a 'lines' array.")
    rem          = remaining_events(db, org_id)
    inserted     = 0
    inserted_ids = []
    with db.cursor() as cur:
        for line in lines:
            if rem is not None and inserted >= rem:
                break
            result = classify_event(str(line))
            if not result:
                continue
            ip, event_type, severity, category, description = result
            cur.execute("""
                INSERT INTO events (org_id, ip_address, event_type, severity, category, description)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
            """, (org_id, ip, event_type, severity, category, description))
            inserted_ids.append(cur.fetchone()["id"])
            inserted += 1
    db.commit()
    if inserted > 0:
        increment_usage(db, org_id, inserted)
        process_alerts(db, org_id, inserted_ids)
    return {"inserted": inserted}, 201

# ---------------------------------------------------------------------------
# Agent download
# ---------------------------------------------------------------------------

@app.route("/agent")
@login_required
def agent_install():
    return render_template("agent.html")


@app.route("/agent/download")
def download_agent():
    from flask import send_file
    agent_path = os.path.join(os.path.dirname(__file__), "logsentry-agent.py")
    return send_file(agent_path, as_attachment=True, download_name="logsentry-agent.py")


# ---------------------------------------------------------------------------
# Landing page + waitlist
# ---------------------------------------------------------------------------

@app.route("/home")
def landing():
    return render_template("landing.html", plans=PLANS)


@app.route("/waitlist", methods=["POST"])
def waitlist_signup():
    data  = request.get_json(silent=True)
    email = (data.get("email") or "").strip().lower() if data else ""
    if not email or "@" not in email:
        return jsonify(error="Please enter a valid email address."), 400
    db = get_db()
    existing = query_one(db, "SELECT id FROM waitlist WHERE email = %s", (email,))
    if existing:
        return jsonify(error="You're already on the list!"), 409
    execute(db, "INSERT INTO waitlist (email) VALUES (%s)", (email,))
    # Send confirmation email
    if resend.api_key:
        try:
            resend.Emails.send({
                "from": ALERT_FROM_EMAIL,
                "to":   [email],
                "subject": "You're on the LogSentry waitlist!",
                "html": """
                    <div style="font-family:sans-serif;background:#0d0f12;color:#e8eaf0;padding:32px;border-radius:8px;max-width:480px;">
                        <h2 style="color:#60a5fa;margin-top:0;">You're on the list 🎉</h2>
                        <p>Thanks for joining the LogSentry waitlist. We're putting the finishing touches on the product and will email you the moment we launch.</p>
                        <p style="margin-top:16px;"><strong>Early access perk:</strong> the first wave of signups gets 3 months of Starter free ($87 value).</p>
                        <p style="color:#6b7280;font-size:14px;margin-top:24px;">— The LogSentry team</p>
                    </div>
                """,
            })
        except Exception as e:
            app.logger.error(f"Waitlist confirmation email failed: {e}")
    return jsonify(ok=True), 201


@app.route("/waitlist/count")
def waitlist_count():
    db  = get_db()
    row = query_one(db, "SELECT COUNT(*) AS n FROM waitlist")
    return jsonify(count=row["n"] if row else 0)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)