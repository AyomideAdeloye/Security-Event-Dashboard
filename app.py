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

def extract_ip(line):
    """Try to extract an IP address from a log line."""
    import re
    match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    return match.group(1) if match else "Unknown"


def extract_account(line):
    """Extract account name from Windows event logs."""
    import re
    match = re.search(r'Account Name:\s+(\S+)', line)
    if match:
        return match.group(1)
    match = re.search(r'Security ID:\s+\S+\(\S+)', line)
    if match:
        return match.group(1)
    return "Unknown"


def classify_event(line: str):
    """
    Classify a single log line from multiple formats:
    - Windows Event Viewer exports
    - Linux syslog / auth.log
    - Nginx / Apache access logs
    - Generic application logs
    """
    line = line.strip()
    if not line:
        return None

    upper = line.upper()
    ip    = extract_ip(line)

    # ── Windows Event IDs ──────────────────────────────────────────────────

    # 4625 = Failed logon
    if "4625" in line:
        account = extract_account(line)
        return ip, "FAILED_LOGIN", "High", "Authentication", f"Windows failed logon — account: {account}"

    # 4648 = Logon using explicit credentials (potential lateral movement)
    if "4648" in line:
        account = extract_account(line)
        return ip, "EXPLICIT_CREDENTIALS", "High", "Authentication", f"Logon with explicit credentials — account: {account}"

    # 4719 = System audit policy changed
    if "4719" in line:
        return ip, "AUDIT_POLICY_CHANGE", "High", "Policy", "System audit policy was changed"

    # 4720 = User account created
    if "4720" in line:
        account = extract_account(line)
        return ip, "ACCOUNT_CREATED", "Medium", "Account Management", f"New user account created: {account}"

    # 4722 = User account enabled
    if "4722" in line:
        account = extract_account(line)
        return ip, "ACCOUNT_ENABLED", "Low", "Account Management", f"User account enabled: {account}"

    # 4723/4724 = Password change attempt
    if "4723" in line or "4724" in line:
        account = extract_account(line)
        return ip, "PASSWORD_CHANGE", "Medium", "Account Management", f"Password change attempt — account: {account}"

    # 4725 = User account disabled
    if "4725" in line:
        account = extract_account(line)
        return ip, "ACCOUNT_DISABLED", "Medium", "Account Management", f"User account disabled: {account}"

    # 4726 = User account deleted
    if "4726" in line:
        account = extract_account(line)
        return ip, "ACCOUNT_DELETED", "High", "Account Management", f"User account deleted: {account}"

    # 4740 = Account lockout
    if "4740" in line:
        account = extract_account(line)
        return ip, "ACCOUNT_LOCKOUT", "High", "Authentication", f"Account locked out: {account}"

    # 4756/4757 = Member added/removed from security group
    if "4756" in line:
        return ip, "GROUP_MEMBER_ADDED", "Medium", "Account Management", "Member added to security-enabled group"
    if "4757" in line:
        return ip, "GROUP_MEMBER_REMOVED", "Medium", "Account Management", "Member removed from security-enabled group"

    # 4771 = Kerberos pre-auth failed
    if "4771" in line:
        account = extract_account(line)
        return ip, "KERBEROS_FAILURE", "High", "Authentication", f"Kerberos pre-authentication failed — account: {account}"

    # 4776 = NTLM auth attempt
    if "4776" in line and "Audit Failure" in line:
        account = extract_account(line)
        return ip, "NTLM_FAILURE", "High", "Authentication", f"NTLM authentication failed — account: {account}"

    # 4672 = Special privileges assigned (admin logon)
    if "4672" in line:
        account = extract_account(line)
        return ip, "PRIVILEGED_LOGON", "Medium", "Authentication", f"Special privileges assigned to new logon — account: {account}"

    # 4624 = Successful logon
    if "4624" in line:
        account = extract_account(line)
        return ip, "AUTH_SUCCESS", "Low", "Authentication", f"Successful Windows logon — account: {account}"

    # 4634/4647 = Logoff
    if "4634" in line or "4647" in line:
        return ip, "LOGOFF", "Low", "Authentication", "User logged off"

    # 4688 = New process created (potential execution)
    if "4688" in line:
        import re
        proc = re.search(r'Process Name:\s+(.+)', line)
        proc_name = proc.group(1).strip() if proc else "Unknown"
        return ip, "PROCESS_CREATED", "Low", "System", f"New process created: {proc_name}"

    # 4698/4702 = Scheduled task created/modified
    if "4698" in line or "4702" in line:
        return ip, "SCHEDULED_TASK", "Medium", "System", "Scheduled task created or modified"

    # 4732 = Member added to local admin group
    if "4732" in line:
        return ip, "ADMIN_GROUP_CHANGE", "High", "Account Management", "Member added to local Administrators group"

    # 4799 = Security group enumeration
    if "4799" in line:
        account = extract_account(line)
        return ip, "GROUP_ENUMERATION", "Low", "Reconnaissance", f"Security group membership enumerated by: {account}"

    # 1102 = Audit log cleared
    if "1102" in line:
        return ip, "LOG_CLEARED", "High", "Tampering", "Security audit log was cleared — possible cover-up attempt"

    # 7045 = New service installed
    if "7045" in line:
        return ip, "SERVICE_INSTALLED", "High", "System", "A new service was installed on the system"

    # ── Windows audit keywords ─────────────────────────────────────────────

    if "AUDIT FAILURE" in upper:
        account = extract_account(line)
        return ip, "AUDIT_FAILURE", "High", "Authentication", f"Windows audit failure — account: {account}"

    if "AUDIT SUCCESS" in upper:
        return ip, "AUDIT_SUCCESS", "Low", "Authentication", "Windows audit success event"

    # ── Linux auth.log patterns ────────────────────────────────────────────

    if "FAILED PASSWORD" in upper or "AUTHENTICATION FAILURE" in upper:
        import re
        user = re.search(r'(?:for|user)\s+(\S+)', line, re.IGNORECASE)
        account = user.group(1) if user else "Unknown"
        return ip, "FAILED_LOGIN", "High", "Authentication", f"SSH failed password — user: {account}"

    if "INVALID USER" in upper or "ILLEGAL USER" in upper:
        import re
        user = re.search(r'(?:invalid user|illegal user)\s+(\S+)', line, re.IGNORECASE)
        account = user.group(1) if user else "Unknown"
        return ip, "INVALID_USER", "High", "Authentication", f"SSH login attempt with invalid user: {account}"

    if "ACCEPTED PASSWORD" in upper or "ACCEPTED PUBLICKEY" in upper:
        import re
        user = re.search(r'for\s+(\S+)', line, re.IGNORECASE)
        account = user.group(1) if user else "Unknown"
        return ip, "AUTH_SUCCESS", "Low", "Authentication", f"SSH login successful — user: {account}"

    if "CONNECTION CLOSED BY AUTHENTICATING USER" in upper:
        return ip, "FAILED_LOGIN", "Medium", "Authentication", "SSH connection closed before authentication completed"

    if "DID NOT RECEIVE IDENTIFICATION" in upper:
        return ip, "SCAN_PROBE", "Medium", "Network", "Port probe — no SSH identification received"

    if "SUDO" in upper and "COMMAND" in upper:
        import re
        cmd = re.search(r'COMMAND=(.*)', line)
        cmd_str = cmd.group(1).strip() if cmd else "Unknown"
        return ip, "SUDO_COMMAND", "Medium", "Privilege Escalation", f"Sudo command executed: {cmd_str}"

    if "SUDO" in upper and ("INCORRECT PASSWORD" in upper or "3 INCORRECT" in upper):
        return ip, "SUDO_FAILURE", "High", "Privilege Escalation", "Failed sudo attempt — incorrect password"

    # ── Nginx / Apache access log patterns ────────────────────────────────

    import re
    http_match = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP', line)
    if http_match:
        status_match = re.search(r'HTTP/\d\.\d"\s+(\d{3})', line)
        status = status_match.group(1) if status_match else "000"
        path   = http_match.group(1)

        # SQL injection / path traversal patterns
        sqli_patterns = ["'", "UNION SELECT", "DROP TABLE", "../", "%2e%2e", "etc/passwd"]
        if any(p.lower() in line.lower() for p in sqli_patterns):
            return ip, "INJECTION_ATTEMPT", "High", "Web Attack", f"Possible injection attempt on {path}"

        if status.startswith("4"):
            return ip, "HTTP_ERROR", "Medium", "Web", f"HTTP {status} on {path}"
        if status.startswith("5"):
            return ip, "SERVER_ERROR", "Medium", "Web", f"HTTP {status} server error on {path}"
        return ip, "HTTP_REQUEST", "Low", "Web", f"HTTP {status} {path}"

    # ── Generic fallback patterns ──────────────────────────────────────────

    if "PORT SCAN" in upper or "PORTSCAN" in upper or "NMAP" in upper:
        return ip, "PORT_SCAN", "High", "Network", "Port scan detected"

    if "SEGFAULT" in upper or "SEGMENTATION FAULT" in upper:
        return ip, "SEGFAULT", "Medium", "System", "Segmentation fault — possible exploit attempt"

    if "OUT OF MEMORY" in upper or "OOM KILLER" in upper:
        return ip, "OOM", "Medium", "System", "Out of memory event detected"

    if "ERROR" in upper:
        return ip, "ERROR", "Medium", "System", "Error event detected"

    if "WARNING" in upper or "WARN" in upper:
        return ip, "WARNING", "Low", "System", "Warning event detected"

    if "CRITICAL" in upper:
        return ip, "CRITICAL", "High", "System", "Critical event detected"

    return ip, "UNKNOWN", "Low", "Uncategorized", "Unclassified event"

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
# Error handlers
# ---------------------------------------------------------------------------

def error_page(code, title, description):
    return render_template("error.html", code=code, title=title, description=description), code

@app.errorhandler(400)
def bad_request(e):
    return error_page(400, "Bad request", str(e.description) if hasattr(e, 'description') else "The request could not be understood.")

@app.errorhandler(401)
def unauthorized(e):
    return error_page(401, "Unauthorized", "You need to log in to access this page.")

@app.errorhandler(403)
def forbidden(e):
    return error_page(403, "Forbidden", "You don't have permission to access this page.")

@app.errorhandler(404)
def not_found(e):
    return error_page(404, "Page not found", "The page you're looking for doesn't exist or has been moved.")

@app.errorhandler(413)
def too_large(e):
    return error_page(413, "File too large", "The file you uploaded exceeds the size limit. Please upload a smaller file or use the API agent instead.")


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