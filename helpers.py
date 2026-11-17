"""
helpers.py - Helper utilities, decorators, and formatting functions.
CS50 Final Project.
"""

from functools import wraps
from flask import session, redirect, url_for, flash, request
from datetime import datetime
import re
from database import execute_db


def login_required(f):
    """
    Decorate routes to require login.
    Adapted from CS50 Finance problem set specification.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Decorate routes to require Administrator privileges.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        if session.get("user_role") != "admin":
            flash("Administrator access required for this action.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


def severity_badge_class(severity: str) -> str:
    """Return Bootstrap badge CSS classes based on incident severity."""
    mapping = {
        "Critical": "bg-danger text-white",
        "High": "bg-warning text-dark",
        "Medium": "bg-primary text-white",
        "Low": "bg-info text-dark"
    }
    return mapping.get(severity, "bg-secondary text-white")


def status_badge_class(status: str) -> str:
    """Return Bootstrap badge CSS classes based on incident status."""
    mapping = {
        "Open": "bg-danger text-white",
        "Investigating": "bg-warning text-dark",
        "Mitigated": "bg-info text-dark",
        "Closed": "bg-success text-white"
    }
    return mapping.get(status, "bg-secondary text-white")


def reputation_badge_class(reputation: str) -> str:
    """Return Bootstrap badge CSS classes based on IOC reputation."""
    mapping = {
        "Malicious": "bg-danger text-white",
        "Suspicious": "bg-warning text-dark",
        "Clean": "bg-success text-white"
    }
    return mapping.get(reputation, "bg-secondary text-white")


def format_datetime(value, format_str="%Y-%m-%d %H:%M:%S"):
    """Format datetime objects or SQLite timestamps for user interface display."""
    if value is None:
        return "N/A"
    if isinstance(value, str):
        try:
            # Handle standard SQLite ISO timestamp format
            dt = datetime.fromisoformat(value)
            return dt.strftime(format_str)
        except ValueError:
            return value
    if isinstance(value, datetime):
        return value.strftime(format_str)
    return str(value)


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate that password meets security requirements:
    At least 8 characters, containing at least one letter and one number.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    return True, ""


def log_activity(action: str, details: str = ""):
    """
    Record an action into the platform activity audit log.
    Captures user_id, action, details, and client IP address.
    """
    user_id = session.get("user_id")
    ip_addr = request.remote_addr if request else "127.0.0.1"
    try:
        execute_db(
            "INSERT INTO activity_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)",
            (user_id, action, details, ip_addr)
        )
    except Exception:
        # Prevent logging failure from breaking primary user flow
        pass
