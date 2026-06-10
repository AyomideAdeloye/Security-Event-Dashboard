#!/usr/bin/env python3
"""
LogSentry Agent
===============
Watches your server log files and ships new events to LogSentry automatically.

Install:
    curl -O https://your-domain/agent/logsentry-agent.py
    pip3 install requests
    python3 logsentry-agent.py --key YOUR_API_KEY --install

Manual run:
    python3 logsentry-agent.py --key YOUR_API_KEY

"""
import os
import sys
import time
import json
import argparse
import logging
import signal
import subprocess
from pathlib import Path

try:
    import requests
except ImportError:
    print("Missing dependency: run 'pip3 install requests' first")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_API_URL = "https://security-event-dashboard-production.up.railway.app/api/ingest"

# Log files to watch by default (most common on Ubuntu/Debian/CentOS)
DEFAULT_LOG_FILES = [
    "/var/log/auth.log",          # SSH logins, sudo, su (Ubuntu/Debian)
    "/var/log/secure",            # SSH logins (CentOS/RHEL)
    "/var/log/syslog",            # General system events (Ubuntu/Debian)
    "/var/log/messages",          # General system events (CentOS/RHEL)
    "/var/log/nginx/access.log",  # Nginx access
    "/var/log/nginx/error.log",   # Nginx errors
    "/var/log/apache2/error.log", # Apache errors
]

BATCH_SIZE    = 50      # Send events in batches of 50
POLL_INTERVAL = 5       # Check for new lines every 5 seconds
STATE_FILE    = os.path.expanduser("~/.logsentry_state.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [LogSentry] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("logsentry")

# ---------------------------------------------------------------------------
# State management (tracks file positions so we don't re-send old lines)
# ---------------------------------------------------------------------------

def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

# ---------------------------------------------------------------------------
# Log shipping
# ---------------------------------------------------------------------------

def ship_lines(api_key, api_url, lines):
    """Send a batch of log lines to the LogSentry API."""
    if not lines:
        return 0
    try:
        resp = requests.post(
            api_url,
            json={"lines": lines},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        if resp.status_code == 201:
            data = resp.json()
            return data.get("inserted", 0)
        elif resp.status_code == 429:
            log.warning("Monthly event limit reached. Upgrade your plan at LogSentry.")
            return 0
        elif resp.status_code == 401:
            log.error("Invalid API key. Check your --key value.")
            sys.exit(1)
        else:
            log.warning(f"API returned {resp.status_code}: {resp.text[:200]}")
            return 0
    except requests.exceptions.ConnectionError:
        log.warning("Could not reach LogSentry API. Will retry next cycle.")
        return 0
    except requests.exceptions.Timeout:
        log.warning("API request timed out. Will retry next cycle.")
        return 0


def tail_file(filepath, state):
    """
    Read new lines from a file since the last known position.
    Returns (new_lines, new_position).
    """
    path = Path(filepath)
    if not path.exists():
        return [], state.get(filepath, 0)

    current_size = path.stat().st_size
    last_pos     = state.get(filepath, 0)

    # File was rotated (new file is smaller than last position)
    if current_size < last_pos:
        log.info(f"Log rotation detected for {filepath}, resetting position.")
        last_pos = 0

    # Nothing new
    if current_size == last_pos:
        return [], last_pos

    new_lines = []
    with open(filepath, "r", errors="replace") as f:
        f.seek(last_pos)
        for line in f:
            line = line.strip()
            if line:
                new_lines.append(line)
        new_pos = f.tell()

    return new_lines, new_pos

# ---------------------------------------------------------------------------
# Systemd service installer
# ---------------------------------------------------------------------------

SYSTEMD_SERVICE = """[Unit]
Description=LogSentry Agent
After=network.target

[Service]
Type=simple
User={user}
ExecStart=/usr/bin/python3 {script_path} --key {api_key} --url {api_url}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

def install_service(api_key, api_url):
    """Install the agent as a systemd service so it runs on boot."""
    if os.geteuid() != 0:
        print("Installing as a service requires sudo. Run: sudo python3 logsentry-agent.py --key YOUR_KEY --install")
        sys.exit(1)

    script_path = os.path.abspath(__file__)
    user        = os.environ.get("SUDO_USER", "root")
    service     = SYSTEMD_SERVICE.format(
        user=user,
        script_path=script_path,
        api_key=api_key,
        api_url=api_url,
    )

    service_path = "/etc/systemd/system/logsentry.service"
    with open(service_path, "w") as f:
        f.write(service)

    subprocess.run(["systemctl", "daemon-reload"],        check=True)
    subprocess.run(["systemctl", "enable", "logsentry"],  check=True)
    subprocess.run(["systemctl", "start",  "logsentry"],  check=True)

    print("✓ LogSentry agent installed and started.")
    print("  Check status:  sudo systemctl status logsentry")
    print("  View logs:     sudo journalctl -u logsentry -f")
    sys.exit(0)

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(api_key, api_url, log_files):
    state         = load_state()
    total_shipped = 0

    # Initialise positions for any new files (start from end, don't re-ship old logs)
    for filepath in log_files:
        if filepath not in state and Path(filepath).exists():
            state[filepath] = Path(filepath).stat().st_size
            log.info(f"Watching {filepath}")

    save_state(state)
    log.info(f"Agent started. Watching {len(log_files)} log files. Sending to {api_url}")

    def handle_exit(sig, frame):
        log.info(f"Agent stopped. Total events shipped this session: {total_shipped}")
        save_state(state)
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_exit)
    signal.signal(signal.SIGINT,  handle_exit)

    while True:
        batch = []

        for filepath in log_files:
            new_lines, new_pos = tail_file(filepath, state)
            if new_lines:
                batch.extend(new_lines)
                state[filepath] = new_pos

        # Ship in batches
        for i in range(0, len(batch), BATCH_SIZE):
            chunk    = batch[i:i + BATCH_SIZE]
            inserted = ship_lines(api_key, api_url, chunk)
            if inserted:
                total_shipped += inserted
                log.info(f"Shipped {inserted} events ({total_shipped} total this session)")

        if batch:
            save_state(state)

        time.sleep(POLL_INTERVAL)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="LogSentry Agent — ships server logs to LogSentry automatically."
    )
    parser.add_argument("--key",     required=True, help="Your LogSentry API key")
    parser.add_argument("--url",     default=DEFAULT_API_URL, help="LogSentry API URL")
    parser.add_argument("--files",   nargs="+", help="Log files to watch (overrides defaults)")
    parser.add_argument("--install", action="store_true", help="Install as a systemd service")
    args = parser.parse_args()

    if args.install:
        install_service(args.key, args.url)

    log_files = args.files if args.files else DEFAULT_LOG_FILES
    log_files = [f for f in log_files if Path(f).exists() or any(
        Path(f).parent.exists() for f in log_files
    )]

    if not log_files:
        log.warning("No log files found at default paths. Specify files with --files.")
        log.warning("Example: python3 logsentry-agent.py --key YOUR_KEY --files /var/log/auth.log")

    run(args.key, args.url, log_files)


if __name__ == "__main__":
    main()