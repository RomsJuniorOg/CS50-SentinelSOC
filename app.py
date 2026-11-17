"""
app.py - SentinelSOC Incident Response & Threat Intelligence Platform.
CS50 Final Project.
"""

import os
import json
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, jsonify, Response
)
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db, close_db, query_db, execute_db
from helpers import (
    login_required, admin_required, severity_badge_class,
    status_badge_class, reputation_badge_class, format_datetime,
    validate_password, log_activity
)
from threat_intel import analyze_ioc
from log_parser import analyze_security_logs

# Initialize Flask Application
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cs50-sentinel-soc-secure-session-key-2026")
app.config["DATABASE"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel.db")

# Register database teardown
app.teardown_appcontext(close_db)

# Register Jinja template helpers
app.jinja_env.filters["severity_badge"] = severity_badge_class
app.jinja_env.filters["status_badge"] = status_badge_class
app.jinja_env.filters["reputation_badge"] = reputation_badge_class
app.jinja_env.filters["format_dt"] = format_datetime


@app.context_processor
def inject_user():
    """Make current logged in user details available to all templates."""
    user_id = session.get("user_id")
    if user_id:
        user = query_db("SELECT id, username, full_name, role FROM users WHERE id = ?", (user_id,), one=True)
        return {"current_user": user}
    return {"current_user": None}


# ==========================================
# AUTHENTICATION ROUTES
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a new SOC analyst account."""
    # Redirect if already logged in
    if session.get("user_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")

        # Validation
        if not username or not full_name or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html", username=username, full_name=full_name)

        if password != confirmation:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, full_name=full_name)

        valid_pw, pw_err = validate_password(password)
        if not valid_pw:
            flash(pw_err, "danger")
            return render_template("register.html", username=username, full_name=full_name)

        # Check for existing user
        existing = query_db("SELECT id FROM users WHERE username = ?", (username,), one=True)
        if existing:
            flash("Username is already taken.", "danger")
            return render_template("register.html", username=username, full_name=full_name)

        # Hash password and insert
        pw_hash = generate_password_hash(password)
        user_id = execute_db(
            "INSERT INTO users (username, hash, role, full_name) VALUES (?, ?, 'analyst', ?)",
            (username, pw_hash, full_name)
        )

        # Automatically log the user in
        session["user_id"] = user_id
        session["username"] = username
        session["user_role"] = "analyst"
        session["full_name"] = full_name

        log_activity("USER_REGISTER", f"New user '{username}' registered.")
        flash("Registration successful! Welcome to SentinelSOC.", "success")
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate and log in an existing user."""
    # Clear session first
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please provide both username and password.", "danger")
            return render_template("login.html", username=username)

        user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
        if not user or not check_password_hash(user["hash"], password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html", username=username)

        # Set session variables
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["user_role"] = user["role"]
        session["full_name"] = user["full_name"]

        log_activity("USER_LOGIN", f"User '{username}' logged in.")
        flash(f"Welcome back, {user['full_name']}!", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log out current user and clear session."""
    log_activity("USER_LOGOUT", f"User '{session.get('username')}' logged out.")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ==========================================
# DASHBOARD & METRICS
# ==========================================

@app.route("/")
@login_required
def index():
    """Main SOC Operations Dashboard."""
    # Aggregate summary metrics
    total_incidents = query_db("SELECT COUNT(*) AS count FROM incidents", one=True)["count"]
    open_incidents = query_db("SELECT COUNT(*) AS count FROM incidents WHERE status = 'Open'", one=True)["count"]
    critical_incidents = query_db("SELECT COUNT(*) AS count FROM incidents WHERE severity = 'Critical' AND status != 'Closed'", one=True)["count"]
    total_iocs = query_db("SELECT COUNT(*) AS count FROM iocs", one=True)["count"]
    malicious_iocs = query_db("SELECT COUNT(*) AS count FROM iocs WHERE reputation = 'Malicious'", one=True)["count"]

    # Recent incidents
    recent_incidents = query_db(
        """
        SELECT i.*, u.full_name AS assigned_name
        FROM incidents i
        LEFT JOIN users u ON i.assigned_to = u.id
        ORDER BY i.created_at DESC
        LIMIT 6
        """
    )

    # Recent activity logs
    recent_activity = query_db(
        """
        SELECT a.*, u.username
        FROM activity_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 8
        """
    )

    metrics = {
        "total": total_incidents,
        "open": open_incidents,
        "critical": critical_incidents,
        "total_iocs": total_iocs,
        "malicious_iocs": malicious_iocs
    }

    return render_template("index.html", metrics=metrics, recent_incidents=recent_incidents, recent_activity=recent_activity)


@app.route("/api/stats")
@login_required
def api_stats():
    """JSON API endpoint returning data for dashboard Chart.js charts."""
    # Severity distribution
    severity_rows = query_db("SELECT severity, COUNT(*) as count FROM incidents GROUP BY severity")
    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for row in severity_rows:
        severity_counts[row["severity"]] = row["count"]

    # Category distribution
    category_rows = query_db("SELECT category, COUNT(*) as count FROM incidents GROUP BY category")
    category_labels = [row["category"] for row in category_rows]
    category_counts = [row["count"] for row in category_rows]

    # Status distribution
    status_rows = query_db("SELECT status, COUNT(*) as count FROM incidents GROUP BY status")
    status_counts = {"Open": 0, "Investigating": 0, "Mitigated": 0, "Closed": 0}
    for row in status_rows:
        status_counts[row["status"]] = row["count"]

    return jsonify({
        "severity": {
            "labels": list(severity_counts.keys()),
            "data": list(severity_counts.values())
        },
        "category": {
            "labels": category_labels,
            "data": category_counts
        },
        "status": {
            "labels": list(status_counts.keys()),
            "data": list(status_counts.values())
        }
    })


# ==========================================
# INCIDENT MANAGEMENT
# ==========================================

@app.route("/incidents")
@login_required
def incidents():
    """List, search, and filter security incidents."""
    severity_filter = request.args.get("severity", "")
    status_filter = request.args.get("status", "")
    category_filter = request.args.get("category", "")
    search_query = request.args.get("q", "").strip()

    sql = """
        SELECT i.*, u.full_name AS assigned_name, creator.username AS creator_name,
               (SELECT COUNT(*) FROM iocs WHERE incident_id = i.id) AS ioc_count
        FROM incidents i
        LEFT JOIN users u ON i.assigned_to = u.id
        LEFT JOIN users creator ON i.created_by = creator.id
        WHERE 1=1
    """
    params = []

    if severity_filter:
        sql += " AND i.severity = ?"
        params.append(severity_filter)
    if status_filter:
        sql += " AND i.status = ?"
        params.append(status_filter)
    if category_filter:
        sql += " AND i.category = ?"
        params.append(category_filter)
    if search_query:
        sql += " AND (i.title LIKE ? OR i.affected_asset LIKE ? OR i.description LIKE ?)"
        wildcard = f"%{search_query}%"
        params.extend([wildcard, wildcard, wildcard])

    sql += " ORDER BY i.created_at DESC"
    incident_list = query_db(sql, params)

    return render_template(
        "incidents.html",
        incidents=incident_list,
        severity_filter=severity_filter,
        status_filter=status_filter,
        category_filter=category_filter,
        search_query=search_query
    )


@app.route("/incidents/new", methods=["GET", "POST"])
@login_required
def incident_new():
    """Create a new security incident."""
    users = query_db("SELECT id, full_name, username FROM users ORDER BY full_name")

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "Medium")
        category = request.form.get("category", "Suspicious Activity")
        affected_asset = request.form.get("affected_asset", "").strip()
        mitre_tactic = request.form.get("mitre_tactic", "Initial Access").strip()
        mitre_technique = request.form.get("mitre_technique", "T1078 - Valid Accounts").strip()
        assigned_to = request.form.get("assigned_to") or None
        initial_ioc = request.form.get("initial_ioc", "").strip()

        # Validation
        if not title or not description or not affected_asset:
            flash("Title, Description, and Affected Asset are required.", "danger")
            return render_template("incident_new.html", users=users)

        incident_id = execute_db(
            """
            INSERT INTO incidents (
                title, description, severity, status, category,
                mitre_tactic, mitre_technique, affected_asset,
                assigned_to, created_by
            ) VALUES (?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)
            """,
            (
                title, description, severity, category,
                mitre_tactic, mitre_technique, affected_asset,
                assigned_to, session["user_id"]
            )
        )

        # Add initial timeline event
        execute_db(
            "INSERT INTO incident_timeline (incident_id, user_id, entry_type, message) VALUES (?, ?, 'Created', ?)",
            (incident_id, session["user_id"], f"Incident created with {severity} severity.")
        )

        # Attach initial IOC if provided
        if initial_ioc:
            analysis = analyze_ioc(initial_ioc)
            notes = " | ".join(analysis["risk_factors"]) if analysis["risk_factors"] else "Initial observable added during intake."
            execute_db(
                """
                INSERT INTO iocs (incident_id, ioc_type, value, threat_score, reputation, enrichment_notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (incident_id, analysis["type"], initial_ioc, analysis["threat_score"], analysis["reputation"], notes)
            )
            execute_db(
                "INSERT INTO incident_timeline (incident_id, user_id, entry_type, message) VALUES (?, ?, 'IOC Added', ?)",
                (incident_id, session["user_id"], f"Attached initial IOC: {initial_ioc} (Score: {analysis['threat_score']})")
            )

        log_activity("INCIDENT_CREATED", f"Incident #{incident_id} ('{title}') created.")
        flash(f"Incident #{incident_id} successfully created!", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    return render_template("incident_new.html", users=users)


@app.route("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    """View incident details, IOCs, timeline history, and action controls."""
    incident = query_db(
        """
        SELECT i.*, u.full_name AS assigned_name, creator.full_name AS creator_name
        FROM incidents i
        LEFT JOIN users u ON i.assigned_to = u.id
        LEFT JOIN users creator ON i.created_by = creator.id
        WHERE i.id = ?
        """,
        (incident_id,),
        one=True
    )

    if not incident:
        flash("Incident not found.", "warning")
        return redirect(url_for("incidents"))

    # Fetch associated IOCs
    iocs = query_db("SELECT * FROM iocs WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,))

    # Fetch timeline
    timeline = query_db(
        """
        SELECT t.*, u.username, u.full_name
        FROM incident_timeline t
        LEFT JOIN users u ON t.user_id = u.id
        WHERE t.incident_id = ?
        ORDER BY t.created_at ASC
        """,
        (incident_id,)
    )

    # Fetch users for assignment update
    users = query_db("SELECT id, full_name, username FROM users ORDER BY full_name")

    return render_template(
        "incident_detail.html",
        incident=incident,
        iocs=iocs,
        timeline=timeline,
        users=users
    )


@app.route("/incidents/<int:incident_id>/update_status", methods=["POST"])
@login_required
def incident_update_status(incident_id):
    """Update incident status, severity, or assigned analyst."""
    new_status = request.form.get("status")
    new_severity = request.form.get("severity")
    new_assignee = request.form.get("assigned_to") or None

    incident = query_db("SELECT status, severity, assigned_to FROM incidents WHERE id = ?", (incident_id,), one=True)
    if not incident:
        flash("Incident not found.", "danger")
        return redirect(url_for("incidents"))

    updates = []
    if new_status and new_status != incident["status"]:
        execute_db("UPDATE incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_status, incident_id))
        execute_db(
            "INSERT INTO incident_timeline (incident_id, user_id, entry_type, message) VALUES (?, ?, 'Status Change', ?)",
            (incident_id, session["user_id"], f"Status changed from {incident['status']} to {new_status}.")
        )
        updates.append(f"Status -> {new_status}")

    if new_severity and new_severity != incident["severity"]:
        execute_db("UPDATE incidents SET severity = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_severity, incident_id))
        execute_db(
            "INSERT INTO incident_timeline (incident_id, user_id, entry_type, message) VALUES (?, ?, 'Severity Change', ?)",
            (incident_id, session["user_id"], f"Severity updated from {incident['severity']} to {new_severity}.")
        )
        updates.append(f"Severity -> {new_severity}")

    if new_assignee != (str(incident["assigned_to"]) if incident["assigned_to"] else None):
        execute_db("UPDATE incidents SET assigned_to = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_assignee, incident_id))
        assignee_name = "Unassigned"
        if new_assignee:
            u = query_db("SELECT full_name FROM users WHERE id = ?", (new_assignee,), one=True)
            if u:
                assignee_name = u["full_name"]
        execute_db(
            "INSERT INTO incident_timeline (incident_id, user_id, entry_type, message) VALUES (?, ?, 'Note', ?)",
            (incident_id, session["user_id"], f"Incident reassigned to {assignee_name}.")
        )
        updates.append(f"Assignee -> {assignee_name}")

    if updates:
        log_activity("INCIDENT_UPDATED", f"Incident #{incident_id} updated: {', '.join(updates)}")
        flash("Incident details updated successfully.", "success")
    else:
        flash("No changes detected.", "info")

    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/add_ioc", methods=["POST"])
@login_required
def incident_add_ioc(incident_id):
    """Analyze and attach a new IOC to an incident."""
    ioc_value = request.form.get("ioc_value", "").strip()
    if not ioc_value:
        flash("Please enter an observable value.", "warning")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    analysis = analyze_ioc(ioc_value)
    notes = " | ".join(analysis["risk_factors"]) if analysis["risk_factors"] else "Analyzed by threat intelligence engine."

    execute_db(
        """
        INSERT INTO iocs (incident_id, ioc_type, value, threat_score, reputation, enrichment_notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (incident_id, analysis["type"], ioc_value, analysis["threat_score"], analysis["reputation"], notes)
    )

    execute_db(
        "INSERT INTO incident_timeline (incident_id, user_id, entry_type, message) VALUES (?, ?, 'IOC Added', ?)",
        (incident_id, session["user_id"], f"Added IOC '{ioc_value}' ({analysis['type']}). Threat score: {analysis['threat_score']}/100 [{analysis['reputation']}].")
    )

    log_activity("IOC_ADDED", f"Added IOC '{ioc_value}' to incident #{incident_id}.")
    flash(f"IOC '{ioc_value}' attached and analyzed successfully!", "success")
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/add_note", methods=["POST"])
@login_required
def incident_add_note(incident_id):
    """Add an investigator note to the incident timeline."""
    note_message = request.form.get("note", "").strip()
    if not note_message:
        flash("Note message cannot be blank.", "warning")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    execute_db(
        "INSERT INTO incident_timeline (incident_id, user_id, entry_type, message) VALUES (?, ?, 'Note', ?)",
        (incident_id, session["user_id"], note_message)
    )

    log_activity("NOTE_ADDED", f"Added note to incident #{incident_id}.")
    flash("Investigation note added.", "success")
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/export_json")
@login_required
def incident_export_json(incident_id):
    """Export complete incident data and investigation history as JSON."""
    incident = query_db("SELECT * FROM incidents WHERE id = ?", (incident_id,), one=True)
    if not incident:
        return "Incident not found", 404

    iocs = query_db("SELECT * FROM iocs WHERE incident_id = ?", (incident_id,))
    timeline = query_db("SELECT * FROM incident_timeline WHERE incident_id = ?", (incident_id,))

    export_payload = {
        "incident": dict(incident),
        "iocs": [dict(row) for row in iocs],
        "timeline": [dict(row) for row in timeline],
        "exported_at": format_datetime(None),
        "exported_by": session.get("username")
    }

    response = Response(
        json.dumps(export_payload, indent=2, default=str),
        mimetype="application/json"
    )
    response.headers["Content-Disposition"] = f"attachment; filename=incident_{incident_id}_export.json"
    return response


# ==========================================
# THREAT INTELLIGENCE & LOG ANALYZER TOOLS
# ==========================================

@app.route("/threat_lookup", methods=["GET", "POST"])
@login_required
def threat_lookup():
    """Standalone Threat Intelligence IOC Lookup & Scoring Tool."""
    result = None
    query_val = ""

    if request.method == "POST":
        query_val = request.form.get("ioc", "").strip()
        if query_val:
            result = analyze_ioc(query_val)
            log_activity("THREAT_LOOKUP", f"Analyzed IOC '{query_val}'. Score: {result['threat_score']}.")

    return render_template("threat_lookup.html", result=result, query_val=query_val)


@app.route("/log_analyzer", methods=["GET", "POST"])
@login_required
def log_analyzer():
    """Security Log Parser and Anomaly Detection Tool."""
    analysis = None
    raw_logs = ""

    if request.method == "POST":
        raw_logs = request.form.get("logs", "")
        if raw_logs.strip():
            analysis = analyze_security_logs(raw_logs)
            log_activity("LOG_ANALYSIS", f"Processed {analysis['total_lines_processed']} log lines. {len(analysis['alerts_generated'])} alerts generated.")
        else:
            flash("Please paste or upload log entries to analyze.", "warning")

    return render_template("log_analyzer.html", analysis=analysis, raw_logs=raw_logs)


@app.route("/activity_logs")
@login_required
def activity_logs():
    """Platform audit log viewer."""
    logs = query_db(
        """
        SELECT a.*, u.username, u.full_name
        FROM activity_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 100
        """
    )
    return render_template("activity_logs.html", logs=logs)


# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
