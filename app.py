from flask import Flask, render_template, request, redirect, g, abort
import sqlite3
import os

app = Flask(__name__)

DB_NAME = "security_events.db"
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS = {".log", ".txt"}
EVENTS_PER_PAGE = 50


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a per-request DB connection stored on Flask's g object."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_NAME)
        g.db.row_factory = sqlite3.Row  # access columns by name
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT,
                event_type  TEXT,
                severity    TEXT,
                category    TEXT,
                description TEXT
            )
        """)
        db.commit()


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

def classify_event(line: str):
    """
    Parse a single log line and return a 5-tuple:
    (ip_address, event_type, severity, category, description)

    Returns None if the line is blank or unparseable.
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split()
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
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    db = get_db()

    total_events  = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    high_events   = db.execute("SELECT COUNT(*) FROM events WHERE severity = 'High'").fetchone()[0]
    failed_logins = db.execute("SELECT COUNT(*) FROM events WHERE event_type = 'FAILED_LOGIN'").fetchone()[0]
    port_scans    = db.execute("SELECT COUNT(*) FROM events WHERE event_type = 'PORT_SCAN'").fetchone()[0]

    return render_template(
        "index.html",
        total_events=total_events,
        high_events=high_events,
        failed_logins=failed_logins,
        port_scans=port_scans,
    )


@app.route("/upload", methods=["POST"])
def upload_logs():
    log_file = request.files.get("log_file")

    if not log_file or not log_file.filename:
        abort(400, "No file provided.")

    # Validate extension
    _, ext = os.path.splitext(log_file.filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        abort(400, f"Invalid file type '{ext}'. Only {ALLOWED_EXTENSIONS} are accepted.")

    # Read with size guard
    raw = log_file.read(MAX_FILE_SIZE + 1)
    if len(raw) > MAX_FILE_SIZE:
        abort(413, "File exceeds the 5 MB limit.")

    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        abort(400, "File must be UTF-8 encoded text.")

    db = get_db()
    inserted = 0
    for line in lines:
        result = classify_event(line)
        if result is None:
            continue
        ip, event_type, severity, category, description = result
        db.execute(
            "INSERT INTO events (ip_address, event_type, severity, category, description) VALUES (?, ?, ?, ?, ?)",
            (ip, event_type, severity, category, description),
        )
        inserted += 1

    db.commit()
    return redirect(f"/events?uploaded={inserted}")


@app.route("/events")
def events():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    offset = (page - 1) * EVENTS_PER_PAGE
    db = get_db()

    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    event_rows = db.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ? OFFSET ?",
        (EVENTS_PER_PAGE, offset),
    ).fetchall()

    total_pages = max(1, (total + EVENTS_PER_PAGE - 1) // EVENTS_PER_PAGE)
    uploaded = request.args.get("uploaded")

    return render_template(
        "events.html",
        event_rows=event_rows,
        page=page,
        total_pages=total_pages,
        total=total,
        uploaded=uploaded,
    )


@app.route("/alerts")
def alerts():
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    offset = (page - 1) * EVENTS_PER_PAGE
    db = get_db()

    total = db.execute("SELECT COUNT(*) FROM events WHERE severity = 'High'").fetchone()[0]
    alert_rows = db.execute(
        "SELECT * FROM events WHERE severity = 'High' ORDER BY id DESC LIMIT ? OFFSET ?",
        (EVENTS_PER_PAGE, offset),
    ).fetchall()

    total_pages = max(1, (total + EVENTS_PER_PAGE - 1) // EVENTS_PER_PAGE)

    return render_template(
        "alerts.html",
        alert_rows=alert_rows,
        page=page,
        total_pages=total_pages,
        total=total,
    )


@app.route("/events/clear", methods=["POST"])
def clear_events():
    db = get_db()
    db.execute("DELETE FROM events")
    db.commit()
    return redirect("/")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    # Never run debug=True in production
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)