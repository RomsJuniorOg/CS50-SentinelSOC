"""
sample_data.py - Seed realistic initial data for SentinelSOC.
CS50 Final Project.
"""

from werkzeug.security import generate_password_hash
from database import init_db, execute_db, query_db
from threat_intel import analyze_ioc


def seed_database():
    """Seed users, incidents, IOCs, and timeline entries for testing and demonstrations."""
    print("[*] Initializing database schema...")
    init_db()

    print("[*] Seeding default users...")
    # Default password for all seed accounts: "Sentinel123!"
    pw_hash = generate_password_hash("Sentinel123!")

    admin_id = execute_db(
        "INSERT INTO users (username, hash, role, full_name) VALUES (?, ?, ?, ?)",
        ("admin", pw_hash, "admin", "SOC Director")
    )
    analyst_id = execute_db(
        "INSERT INTO users (username, hash, role, full_name) VALUES (?, ?, ?, ?)",
        ("analyst", pw_hash, "analyst", "Jane Doe - Tier 2 Analyst")
    )
    hunter_id = execute_db(
        "INSERT INTO users (username, hash, role, full_name) VALUES (?, ?, ?, ?)",
        ("hunter", pw_hash, "analyst", "Carlos Silva - Threat Hunter")
    )

    print("[*] Seeding security incidents...")
    # Incident 1: Cobalt Strike Beacon on Domain Controller
    inc1_id = execute_db(
        """
        INSERT INTO incidents (
            title, description, severity, status, category,
            mitre_tactic, mitre_technique, affected_asset,
            assigned_to, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Cobalt Strike Beacon Activity on Domain Controller DC01",
            "EDR flagged suspicious PowerShell command execution injecting unbacked shellcode into lsass.exe process on primary DC.",
            "Critical",
            "Investigating",
            "Malware",
            "Execution",
            "T1059.001 - Command and Scripting Interpreter: PowerShell",
            "DC01.corp.internal (10.0.0.10)",
            hunter_id,
            admin_id
        )
    )

    # Incident 2: Brute Force on VPN
    inc2_id = execute_db(
        """
        INSERT INTO incidents (
            title, description, severity, status, category,
            mitre_tactic, mitre_technique, affected_asset,
            assigned_to, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Distributed SSH / VPN Brute Force Attack from Known Tor Relays",
            "Over 1,200 authentication failures recorded against external gateway within 15 minutes targeting executive account names.",
            "High",
            "Mitigated",
            "Unauthorized Access",
            "Credential Access",
            "T1110 - Brute Force",
            "vpn-gw01.company.com (198.51.100.1)",
            analyst_id,
            analyst_id
        )
    )

    # Incident 3: Phishing Campaign
    inc3_id = execute_db(
        """
        INSERT INTO incidents (
            title, description, severity, status, category,
            mitre_tactic, mitre_technique, affected_asset,
            assigned_to, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Targeted Phishing Email Campaign Masquerading as M365 Password Reset",
            "Three employees in Finance reported receiving an email with a deceptive link leading to a lookalike Microsoft authentication portal.",
            "Medium",
            "Closed",
            "Phishing",
            "Initial Access",
            "T1566.002 - Phishing: Spearphishing Link",
            "finance-workstation-04.corp.internal",
            analyst_id,
            admin_id
        )
    )

    # Incident 4: Web Application SQL Injection Probing
    inc4_id = execute_db(
        """
        INSERT INTO incidents (
            title, description, severity, status, category,
            mitre_tactic, mitre_technique, affected_asset,
            assigned_to, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Automated SQL Injection & Reconnaissance Probe on Customer Portal",
            "WAF logs captured sqlmap automated test payloads targeting customer login and search endpoints.",
            "Medium",
            "Open",
            "Web Attack",
            "Initial Access",
            "T1190 - Exploit Public-Facing Application",
            "portal.company.com (203.0.113.45)",
            None,
            hunter_id
        )
    )

    # Incident 5: PHP2Shell RCE Exploit & Scanner Campaign (CVE-2026-109618)
    inc5_id = execute_db(
        """
        INSERT INTO incidents (
            title, description, severity, status, category,
            mitre_tactic, mitre_technique, affected_asset,
            assigned_to, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Cloud WAF: PHP2Shell RCE Exploit or Scanner Attempt (CVE-2026-109618)",
            "Cloud WAF rule RD1360 triggered: Detected HTTP requests with automated PHP2Shell tooling User-Agents and PHP easter-egg probe signatures targeting production Apache/PHP application clusters.",
            "High",
            "Investigating",
            "Web Attack",
            "Initial Access",
            "T1190 - Exploit Public-Facing Application",
            "app-cluster-prod.corp.internal (198.51.100.77)",
            analyst_id,
            admin_id
        )
    )

    print("[*] Attaching IOCs with Threat Intelligence enrichment...")
    iocs_to_insert = [
        # Inc 1
        (inc1_id, "45.142.214.18"),
        (inc1_id, "a14db288b8efcbb9d06b3a0bcf4890fb916a03767cb4a26e843e91122e25d2be"),
        (inc1_id, "c2-beacon-tunnel.top"),
        # Inc 2
        (inc2_id, "185.220.101.5"),
        (inc2_id, "194.26.29.112"),
        # Inc 3
        (inc3_id, "login-microsoft-auth-verify.com"),
        (inc3_id, "http://login-microsoft-auth-verify.com/token/login.php?user=finance"),
        # Inc 4
        (inc4_id, "103.151.125.9"),
        # Inc 5 (PHP2Shell)
        (inc5_id, "198.51.100.77")
    ]

    for inc_id, val in iocs_to_insert:
        analysis = analyze_ioc(val)
        notes = " | ".join(analysis["risk_factors"]) if analysis["risk_factors"] else "Observable analyzed."
        execute_db(
            """
            INSERT INTO iocs (
                incident_id, ioc_type, value, threat_score, reputation, enrichment_notes
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (inc_id, analysis["type"], val, analysis["threat_score"], analysis["reputation"], notes)
        )

    print("[*] Adding investigation timeline records...")
    timeline_entries = [
        (inc1_id, admin_id, "Created", "Incident created after EDR automated high-fidelity alert."),
        (inc1_id, hunter_id, "IOC Added", "Attached suspected C2 teamserver IP 45.142.214.18 and Mimikatz SHA256."),
        (inc1_id, hunter_id, "Note", "Isolated DC01 host from subnet and initiated memory dump analysis."),
        (inc2_id, analyst_id, "Created", "Gateway SIEM rule triggered: >1000 failed auths."),
        (inc2_id, analyst_id, "Status Change", "Status updated from Open to Mitigated after IP blocklist applied."),
        (inc3_id, admin_id, "Created", "Phishing report submitted via Outlook Report Phish add-in."),
        (inc3_id, analyst_id, "Status Change", "Status updated to Closed. Malicious domain blocked on DNS resolvers, 0 users supplied credentials."),
        (inc5_id, admin_id, "Created", "Cloud WAF rule RD1360 triggered after automated PHP2Shell probe activity."),
        (inc5_id, analyst_id, "Note", "Initiated WAF IP block for 198.51.100.77 and scheduled emergency PHP patch maintenance.")
    ]

    for inc_id, u_id, entry_t, msg in timeline_entries:
        execute_db(
            "INSERT INTO incident_timeline (incident_id, user_id, entry_type, message) VALUES (?, ?, ?, ?)",
            (inc_id, u_id, entry_t, msg)
        )

    print("[*] Recording platform audit logs...")
    execute_db(
        "INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)",
        (admin_id, "SYSTEM_SEED", "Seeded platform with demo security dataset.")
    )

    print("[+] Database seeding completed successfully!")
    print("    Default login: username='admin', password='Sentinel123!'")
    print("    Alternative:   username='analyst', password='Sentinel123!'")


if __name__ == "__main__":
    seed_database()
