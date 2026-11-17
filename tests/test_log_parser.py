"""
test_log_parser.py - Unit tests for the Security Log Parsing and Detection Engine.
CS50 Final Project.
"""

from log_parser import (
    parse_web_log_line,
    parse_auth_log_line,
    analyze_security_logs
)


def test_parse_web_log_line():
    line = '192.168.1.100 - - [16/Nov/2026:22:15:30 +0000] "GET /login.php HTTP/1.1" 200 4522 "-" "Mozilla/5.0"'
    parsed = parse_web_log_line(line)
    assert parsed is not None
    assert parsed["source_ip"] == "192.168.1.100"
    assert parsed["method"] == "GET"
    assert parsed["path"] == "/login.php"
    assert parsed["status_code"] == 200


def test_parse_auth_log_failed_ssh():
    line = "Nov 16 22:10:01 web01 sshd[28410]: Failed password for root from 198.51.100.44 port 48122 ssh2"
    parsed = parse_auth_log_line(line)
    assert parsed is not None
    assert parsed["type"] == "auth"
    assert parsed["sub_type"] == "ssh_failed"
    assert parsed["source_ip"] == "198.51.100.44"
    assert parsed["user"] == "root"


def test_analyze_security_logs_brute_force():
    logs = """
Nov 16 22:10:01 web01 sshd[28410]: Failed password for root from 198.51.100.44 port 48122 ssh2
Nov 16 22:10:04 web01 sshd[28412]: Failed password for admin from 198.51.100.44 port 48124 ssh2
Nov 16 22:10:07 web01 sshd[28415]: Failed password for test from 198.51.100.44 port 48126 ssh2
Nov 16 22:10:10 web01 sshd[28418]: Failed password for user from 198.51.100.44 port 48128 ssh2
"""
    analysis = analyze_security_logs(logs)
    assert analysis["total_lines_processed"] == 4
    assert analysis["summary"]["failed_logins"] == 4
    assert len(analysis["alerts_generated"]) >= 1

    alert = analysis["alerts_generated"][0]
    assert "Brute Force" in alert["title"]
    assert alert["source_ip"] == "198.51.100.44"
    assert alert["mitre_technique"] == "T1110 - Brute Force"


def test_analyze_security_logs_sqli_and_traversal():
    logs = """
203.0.113.88 - - [16/Nov/2026:22:12:01 +0000] "GET /products.php?id=1' UNION SELECT null,username,password FROM users-- HTTP/1.1" 200 4812 "-" "Mozilla/5.0"
203.0.113.88 - - [16/Nov/2026:22:12:09 +0000] "GET /view.php?file=../../../../etc/passwd HTTP/1.1" 404 280 "-" "Mozilla/5.0"
"""
    analysis = analyze_security_logs(logs)
    assert analysis["summary"]["sqli_count"] == 1
    assert analysis["summary"]["traversal_count"] == 1

    titles = [a["title"] for a in analysis["alerts_generated"]]
    assert any("SQL Injection" in t for t in titles)
    assert any("Traversal" in t for t in titles)


def test_analyze_security_logs_php2shell():
    logs = """
198.51.100.77 - - [16/Nov/2026:22:13:30 +0000] "GET /index.php?=PHPE9568F34-D428-11d2-A769-00AA001ACF42 HTTP/1.1" 200 2520 "-" "php2shell-scan/1.2"
198.51.100.77 - - [16/Nov/2026:22:13:35 +0000] "POST /upload.php?action=php2shell HTTP/1.1" 403 450 "-" "shellflow-php2shell"
"""
    analysis = analyze_security_logs(logs)
    assert analysis["summary"]["php2shell_count"] == 2
    titles = [a["title"] for a in analysis["alerts_generated"]]
    assert any("PHP2Shell" in t for t in titles)

    alert = next(a for a in analysis["alerts_generated"] if "PHP2Shell" in a["title"])
    assert alert["severity"] == "High"
    assert alert["mitre_technique"] == "T1190 - Exploit Public-Facing Application"
    assert "CVE-2026-109618" in alert["description"]

