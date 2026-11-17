# SentinelSOC - Security Operations Center & Threat Intelligence Platform

#### Video Demo: <https://youtu.be/e3RxdZMkYoA>

---

## 1. Project Overview & Motivation

**SentinelSOC** is a full-featured, web-based Security Operations Center (SOC) incident response and threat intelligence platform built using Python, Flask, SQLite, and modern frontend technologies (Bootstrap 5, Chart.js, and FontAwesome). 

In modern cybersecurity operations, incident responders and SOC analysts are constantly inundated with security telemetry from firewalls, endpoint detection and response (EDR) agents, intrusion detection systems (IDS), and web application firewalls (WAF). Triaging these alerts manually using fragmented tools leads to fatigue, missed indicators of compromise (IOCs), and delayed incident containment.

SentinelSOC was conceived and designed to solve this exact problem: providing security teams with an integrated, unified workspace that combines:
1. **Incident Case Management**: Full lifecycle management (Open, Investigating, Mitigated, Closed) with MITRE ATT&CK enterprise matrix tagging, severity scoring, and chronological investigation audit logs.
2. **Automated Threat Intelligence & IOC Scoring Engine**: Algorithmic classification and risk assessment of observables (IPv4 addresses, domains, URLs, and cryptographic MD5/SHA256 hashes), computing a normalized threat score (0–100), Shannon entropy analysis to detect Domain Generation Algorithms (DGA), and specific containment playbooks.
3. **Security Log Parser & Anomaly Detection**: Ingestion engine that parses raw multi-format security logs (Linux `auth.log` / SSH logins, Apache/Nginx web access logs) to correlate events and identify high-fidelity attack patterns: SSH brute force, SQL Injection (SQLi), Directory Traversal, and the real-world **PHP2Shell RCE Exploit / Scanner campaign (CVE-2026-109618 / CVE-2026-109619)**.
4. **Executive & Operational Telemetry Dashboard**: Visual metrics and Chart.js graphs displaying real-time incident severity breakdown, attack vector distribution, and platform audit logs.
5. **Auditing & JSON Export**: Complete auditability with an immutable activity log and single-click JSON export for sharing post-incident summaries with external stakeholders or forensic archives.

---

## 2. Distinctiveness and Complexity

SentinelSOC is distinctly different from the standard CS50 problem sets (such as CS50 Finance or Birthdays) in both scope and architectural complexity:

- **Domain-Specific Logic**: Beyond basic CRUD, SentinelSOC implements cybersecurity algorithms including Shannon entropy calculation for detecting algorithmic DGA domains, regex-based signature matching for OWASP Top 10 web injection attacks, and heuristic Threat Intelligence scoring.
- **Relational Integrity & Schema Design**: The application uses a normalized SQLite schema with 5 interrelated tables (`users`, `incidents`, `iocs`, `incident_timeline`, `activity_logs`), foreign key constraints (`PRAGMA foreign_keys = ON`), cascading deletions, and performance indexing.
- **Comprehensive Defense-in-Depth**: Follows OWASP security best practices:
  - Cryptographic password hashing with `werkzeug.security.generate_password_hash` using salted PBKDF2.
  - Strict parameterization on all SQL queries via helper wrappers to guarantee 100% protection against SQL Injection.
  - Contextual authentication decorators (`@login_required`, `@admin_required`) preventing Broken Access Control.
  - Sanitization of user input and dynamic escaping in Jinja2 templates preventing Cross-Site Scripting (XSS).
- **Automated Test Suite**: Tested with 20 comprehensive unit and integration tests using `pytest` covering route authentication, IOC classification, log correlation rules, and session state.

---

## 3. Detailed File Breakdown

Below is a breakdown of every file created in the project repository and its role:

```
CS50/
├── app.py                     # Main Flask web application, routing, and controller logic
├── database.py                # SQLite database connection manager and context lifecycle
├── helpers.py                 # Decorators (login_required), UI badges, password validators
├── threat_intel.py            # Threat Intelligence enrichment and IOC scoring engine
├── log_parser.py              # Security log parsing and rule-based anomaly detector
├── schema.sql                 # SQL database table definitions, foreign keys, and indexes
├── sample_data.py             # Database seeder with realistic incidents, IOCs, and users
├── requirements.txt           # Pinned production Python dependencies (Flask, Werkzeug, pytest)
├── pytest.ini                 # Pytest configuration and test path definitions
├── .gitignore                 # Excludes bytecode, SQLite databases, caches, and virtualenvs
├── README.md                  # Comprehensive Harvard CS50 documentation
├── static/
│   ├── css/
│   │   └── style.css          # Custom dark SOC theme, cyber glow accents, timeline styling
│   └── js/
│       ├── main.js            # Auto-dismissing flash alerts and clipboard utility
│       └── dashboard.js       # Chart.js asynchronous initialization fetching /api/stats
├── templates/
│   ├── layout.html            # Master Jinja2 template with responsive navbar, footer, flashes
│   ├── index.html             # Executive SOC dashboard with metric cards and Chart.js graphs
│   ├── login.html             # Analyst authentication page with quick demo credentials
│   ├── register.html          # Self-enrollment form with password complexity validation
│   ├── incidents.html         # Incident directory with full-text search and multi-criteria filters
│   ├── incident_new.html      # Incident intake form with MITRE ATT&CK selection & initial IOC
│   ├── incident_detail.html   # Investigation workspace: overview, IOC table, timeline, controls
│   ├── threat_lookup.html     # Standalone Threat Intelligence tool with test sample buttons
│   ├── log_analyzer.html      # Ingestion tool for logs with 1-click incident escalation
│   ├── activity_logs.html     # Immutable platform audit trail
│   ├── 404.html               # Custom cybersecurity-themed 404 error page
│   └── 500.html               # Custom 500 internal server error page
├── sample_logs/
│   ├── auth_failures.log      # Sample SSH authentication brute-force log for testing
│   └── web_attacks.log        # Sample web access log with SQLi and directory traversal attempts
└── tests/
    ├── __init__.py            # Test package identifier
    ├── test_app.py            # Integration tests for routes, authentication, and database
    ├── test_threat_intel.py   # Unit tests for IOC classification, Shannon entropy, and scoring
    └── test_log_parser.py     # Unit tests for log parsing regexes and anomaly detection rules
```

### Detailed Summary of Core Files

#### `app.py`
The controller and heart of the application. It initializes the Flask framework, defines session security, registers Jinja template filters (such as `severity_badge` and `format_dt`), and maps all HTTP endpoints:
- User authentication (`/login`, `/register`, `/logout`).
- Dashboard & Chart metrics (`/`, `/api/stats`).
- Incident case management (`/incidents`, `/incidents/new`, `/incidents/<id>`, `/incidents/<id>/update_status`, `/incidents/<id>/add_ioc`, `/incidents/<id>/add_note`, `/incidents/<id>/export_json`).
- Threat intelligence lookup (`/threat_lookup`).
- Security log parsing (`/log_analyzer`).
- System auditing (`/activity_logs`).
- Custom HTTP exception handlers (`404` and `500`).

#### `database.py`
Provides an abstraction layer over Python's built-in `sqlite3` module. It defines `get_db()`, which stores the database connection inside Flask's request lifecycle `g` object when running as a web app, or creates a standalone connection when executed by scripts or tests. It configures `sqlite3.Row` for dictionary-like column access and enforces SQLite foreign key checks with `PRAGMA foreign_keys = ON`. It also exposes helper functions `query_db()` and `execute_db()` that mandate parameterized arguments to eliminate SQL injection vulnerabilities.

#### `schema.sql`
Defines the relational architecture:
- `users`: Stores analyst identities, password hashes, and roles (`admin`, `analyst`).
- `incidents`: Stores incident tickets, including title, description, severity (`Low`, `Medium`, `High`, `Critical`), lifecycle status (`Open`, `Investigating`, `Mitigated`, `Closed`), attack category, MITRE ATT&CK tactic/technique, affected asset, and user foreign keys.
- `iocs`: Stores indicators linked to an incident (`IPv4`, `Domain`, `URL`, `Hash_MD5`, `Hash_SHA256`), threat score (0-100), reputation, and enrichment findings.
- `incident_timeline`: Chronological audit trail of notes, status changes, and evidence additions per incident.
- `activity_logs`: System-wide audit log capturing every critical action with timestamps and user IP addresses.

#### `threat_intel.py`
The threat scoring module. It identifies observable types through regular expressions and Python's `ipaddress` library. It determines whether an IP is private (RFC 1918) or public. It computes Shannon entropy on domain names ($H(X) = -\sum P(x) \log_2 P(x)$) to detect high-entropy DGA malware domains. It matches signatures against known malware families (e.g. WannaCry ransomware, Mimikatz, Cobalt Strike Beacons, Emotet) and calculates a normalized 0–100 threat score alongside actionable containment recommendations.

#### `log_parser.py`
The detection engine that parses raw security logs. It supports standard Apache/Nginx Combined Log format and Linux `auth.log` format. It correlates sequential log entries to detect:
1. **SSH Brute Force**: Triggers an alert when 3 or more failed login attempts target a host from the same source IP.
2. **SQL Injection (SQLi)**: Identifies boolean-based, UNION-based, and information schema probing payloads in HTTP requests.
3. **Path Traversal**: Flags directory traversal attempts attempting to access `/etc/passwd`, `win.ini`, or encoded variations (`..%2F`).
4. **Vulnerability Scanners**: Identifies automated tools like `sqlmap`, `nikto`, `gobuster`, or `nmap` based on User-Agent signatures.
5. **PHP2Shell RCE Exploit or Scanner Attempt (CVE-2026-109618 / CVE-2026-109619)**: Modeled after enterprise Cloud WAF detection engineering (rule RD1360). Detects exploitation toolings (`php2shell-scan`, `shellflow-php2shell`, `ImpervaPHP2ShellChecker`) and PHP Easter Egg payload probes (`PHPE9568F34...`, `PHPB8B5F2A0...`).

#### `helpers.py`
Utility module providing the `@login_required` decorator (adapted and refined from CS50 Finance) to guard protected routes against unauthenticated access, the `@admin_required` decorator for role-based controls, UI badge mapping functions for Bootstrap, date/time formatters, password strength validators (requiring minimum 8 characters, letters, and numbers), and the `log_activity()` function that populates the audit trail.

#### `sample_data.py`
A seeding script that initializes `sentinel.db` from `schema.sql` and populates realistic demo data: 3 user accounts (`admin`, `analyst`, `hunter`), 5 real-world security incidents (Cobalt Strike on a Domain Controller, Distributed Brute Force on a VPN Gateway, Phishing Campaign targeting Finance, Web Application SQL Injection probing, and Cloud WAF PHP2Shell RCE campaign), enriched IOCs, investigation timeline entries, and activity logs.

---

## 4. Key Design Decisions

1. **Why Flask Instead of Django?**
   Flask is lightweight, unopinionated, and transparent. While Django provides built-in admin panels and ORMs, building SentinelSOC on Flask required writing raw, parameterized SQL queries, explicit session handling, and custom modular business logic—demonstrating a deep understanding of core web fundamentals, database constraints, and HTTP request lifecycles aligned with CS50's pedagogical goals.

2. **Why SQLite for the Database?**
   SQLite requires zero server configuration and stores the entire database in a single portable file (`sentinel.db`), making it ideal for evaluation, automated testing, and standalone demonstrations. By enabling `PRAGMA foreign_keys = ON` and structuring indexes, SQLite achieves enterprise-grade relational integrity and millisecond response times.

3. **Security by Design**:
   - **SQL Injection Prevention**: Every SQL statement in the application uses parameterized `?` placeholders. No string concatenation or formatted strings are ever used in SQL queries.
   - **Password Security**: Passwords are never stored in plaintext. They are hashed using Werkzeug's `generate_password_hash` with PBKDF2-HMAC-SHA256 and salted.
   - **XSS Protection**: Jinja2 auto-escapes HTML variables by default. Sensitive raw values (such as IOC strings) are rendered securely.

4. **Modern Responsive Dark Theme**:
   Security Operation Centers operate in low-light environments. SentinelSOC features a tailored dark interface utilizing Bootstrap 5's dark mode, custom cyber-accent variables, responsive tables, and interactive Chart.js visualizations that adjust dynamically across desktops, tablets, and mobile screens.

---

## 5. How to Setup and Run the Application

### Prerequisites
- Python 3.10 or higher
- `pip` (Python package installer)

### Step-by-Step Installation

1. **Navigate to the project directory**:
   ```bash
   cd c:\Projetos\Cursos\CS50
   ```

2. **Create and activate a virtual environment**:
   - On Windows (PowerShell):
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - On Linux / macOS / CS50 Codespace:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize and seed the database**:
   Run the seeding script to create `sentinel.db` with realistic security incidents and sample analyst accounts:
   ```bash
   python sample_data.py
   ```

5. **Start the Flask development server**:
   ```bash
   python app.py
   ```
   *Or using Flask CLI:*
   ```bash
   flask run
   ```

6. **Access the application**:
   Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## 6. Pre-configured Login Credentials

For demonstration and evaluation purposes, the database includes pre-configured accounts:

| Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **SOC Director (Admin)** | `admin` | `Sentinel123!` | Full Admin & Analyst Privileges |
| **Security Analyst (Tier 2)** | `analyst` | `Sentinel123!` | Incident Triage & Investigation |
| **Threat Hunter** | `hunter` | `Sentinel123!` | IOC Enrichment & Threat Analysis |

*New analyst accounts can also be created at any time via the `/register` page.*

---

## 7. How to Test and Verify

### Running the Automated Test Suite
The project includes a full test suite with 20 tests covering routes, authentication, threat intelligence logic, and log parsing.

Run the tests using `pytest`:
```bash
python -m pytest -v
```

Expected output:
```
============================= test session starts =============================
collected 20 items

tests/test_app.py::test_index_redirects_unauthenticated PASSED           [  5%]
tests/test_app.py::test_login_successful PASSED                          [ 10%]
tests/test_app.py::test_login_invalid_credentials PASSED                 [ 15%]
tests/test_app.py::test_register_validation PASSED                       [ 20%]
tests/test_app.py::test_api_stats_endpoint PASSED                        [ 25%]
tests/test_app.py::test_create_and_view_incident PASSED                  [ 30%]
tests/test_app.py::test_threat_lookup_endpoint PASSED                    [ 35%]
tests/test_log_parser.py::test_parse_web_log_line PASSED                 [ 40%]
tests/test_log_parser.py::test_parse_auth_log_failed_ssh PASSED          [ 45%]
tests/test_log_parser.py::test_analyze_security_logs_brute_force PASSED  [ 50%]
tests/test_log_parser.py::test_analyze_security_logs_sqli_and_traversal PASSED [ 55%]
tests/test_log_parser.py::test_analyze_security_logs_php2shell PASSED    [ 60%]
tests/test_threat_intel.py::test_identify_ioc_type_ipv4 PASSED           [ 65%]
tests/test_threat_intel.py::test_identify_ioc_type_hashes PASSED         [ 70%]
tests/test_threat_intel.py::test_identify_ioc_type_domains_and_urls PASSED [ 75%]
tests/test_threat_intel.py::test_shannon_entropy PASSED                  [ 80%]
tests/test_threat_intel.py::test_analyze_internal_ip PASSED              [ 85%]
tests/test_threat_intel.py::test_analyze_known_malicious_ip PASSED       [ 90%]
tests/test_threat_intel.py::test_analyze_known_malware_hash PASSED       [ 95%]
tests/test_threat_intel.py::test_analyze_phishing_domain_with_suspicious_tld PASSED [100%]

============================= 20 passed in 4.70s ==============================
```

### Manual Feature Walkthrough
1. **Dashboard**: Navigate to `/` to view active investigations, threat metrics, and Chart.js graphs.
2. **Incidents Management**: Navigate to `/incidents` to filter cases by severity or status. Click **"New Incident"** to log a ticket with MITRE ATT&CK techniques.
3. **Investigation Detail**: Open any incident (e.g. Incident `#1`), attach new observables, add investigator notes to the timeline, update status from *Investigating* to *Mitigated*, or click **"Export JSON Report"** to download an incident report.
4. **Threat Intelligence Lookup**: Navigate to `/threat_lookup` and test sample IOCs (e.g., Cobalt Strike IP `45.142.214.18`, WannaCry hash `ed01ebf83334a1bfa188f3071f0947aa586c7da3cb7b58410e767d8e84a1e5d1`, or internal IP `10.0.0.1`).
5. **Log Analyzer & Anomaly Detection**: Navigate to `/log_analyzer`, click **"Preload SSH Brute-Force"** or **"Preload Web SQLi & Traversal"**, execute the parser, review the detection alerts, and click **"Escalate to Incident Case"** to convert a detected attack directly into an active ticket.
6. **Audit Trail**: Navigate to `/activity_logs` to review the record of all analyst and system events.

---

## 8. Video Demo Submission Guidelines

As required by Harvard CS50:
- Prepare a short video overview (up to 3 minutes in length).
- In the video, state your name, your city and country, the title of your project (**SentinelSOC**), and demonstrate the application's key features: logging in, walking through the dashboard, creating an incident, looking up an IOC in the Threat Intelligence tool, analyzing a raw log in the Log Analyzer, and exporting a case.
- Upload your recording to YouTube as **Public** or **Unlisted**.
- Video link set: `<https://youtu.be/e3RxdZMkYoA>`. Ready for final submission!
