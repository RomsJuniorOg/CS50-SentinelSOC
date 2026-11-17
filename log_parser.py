"""
log_parser.py - Security Log Parsing and Anomaly Detection Engine.
CS50 Final Project.
"""

import re
from datetime import datetime
from collections import defaultdict


# Signatures for web attacks
SQLI_PATTERNS = [
    re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
    re.compile(r"\b(UNION(\s+ALL)?\s+SELECT)\b", re.IGNORECASE),
    re.compile(r"\b(OR\s+[\'\"]?1[\'\"]?\s*=\s*[\'\"]?1)\b", re.IGNORECASE),
    re.compile(r"\b(AND\s+[\'\"]?1[\'\"]?\s*=\s*[\'\"]?1)\b", re.IGNORECASE),
    re.compile(r"\b(SELECT\s+.+\s+FROM\s+information_schema)\b", re.IGNORECASE),
    re.compile(r"\b(SLEEP\(\d+\)|BENCHMARK\(\d+)\b", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e/|\.\.%2f)", re.IGNORECASE),
    re.compile(r"(/etc/passwd|/etc/shadow|/proc/self/environ|win.ini|boot.ini)", re.IGNORECASE)
]

SCANNER_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster",
    "acunetix", "wpscan", "hydra", "burpcollaborator"
]

# Signatures for PHP2Shell RCE (CVE-2026-109618 / CVE-2026-109619)
PHP2SHELL_UA_PATTERN = re.compile(
    r"(php2shell|shellflow-php2shell|SOCRadarLabs.*php2shell|ImpervaPHP2ShellChecker)",
    re.IGNORECASE
)

PHP2SHELL_PAYLOAD_PATTERN = re.compile(
    r"(php2shell|[?&]=(PHPE9568F3[456]-D428-11d2-A769-00AA001ACF42|PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000))",
    re.IGNORECASE
)


def parse_web_log_line(line: str) -> dict:
    """
    Parse a standard Common / Combined Log Format (Apache / Nginx).
    Example: 192.168.1.100 - - [16/Nov/2026:22:15:30 +0000] "GET /login.php?id=1' OR '1'='1 HTTP/1.1" 200 4522 "-" "sqlmap/1.5"
    """
    pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (.*?) (\S+)" (\d{3}) (\S+) "(.*?)" "(.*?)"'
    match = re.match(pattern, line.strip())
    if match:
        ip, raw_time, method, path, proto, status, size, referer, user_agent = match.groups()
        return {
            "type": "web",
            "source_ip": ip,
            "timestamp": raw_time,
            "method": method,
            "path": path,
            "status_code": int(status),
            "user_agent": user_agent,
            "raw": line.strip()
        }

    # Fallback simpler regex for Common Log Format without referer/UA
    simpler_pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (.*?) (\S+)" (\d{3}) (\S+)'
    match = re.match(simpler_pattern, line.strip())
    if match:
        ip, raw_time, method, path, proto, status, size = match.groups()
        return {
            "type": "web",
            "source_ip": ip,
            "timestamp": raw_time,
            "method": method,
            "path": path,
            "status_code": int(status),
            "user_agent": "Unknown",
            "raw": line.strip()
        }

    return None


def parse_auth_log_line(line: str) -> dict:
    """
    Parse Linux auth.log / secure log entries (SSH logins, sudo events).
    Example: Nov 16 22:14:02 srv-prod sshd[14221]: Failed password for root from 192.168.1.200 port 55412 ssh2
    """
    line_clean = line.strip()

    # Failed SSH password
    failed_match = re.search(r"sshd\[\d+\]: Failed password for (invalid user )?(\S+) from (\S+) port \d+", line_clean)
    if failed_match:
        invalid, username, ip = failed_match.groups()
        return {
            "type": "auth",
            "sub_type": "ssh_failed",
            "source_ip": ip,
            "user": username,
            "action": "Failed Login",
            "raw": line_clean
        }

    # Accepted SSH password / key
    accepted_match = re.search(r"sshd\[\d+\]: Accepted (password|publickey) for (\S+) from (\S+) port \d+", line_clean)
    if accepted_match:
        auth_type, username, ip = accepted_match.groups()
        return {
            "type": "auth",
            "sub_type": "ssh_accepted",
            "source_ip": ip,
            "user": username,
            "action": f"Accepted ({auth_type})",
            "raw": line_clean
        }

    # Sudo usage
    sudo_match = re.search(r"sudo:\s+(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)", line_clean)
    if sudo_match:
        invoker, target_user, cmd = sudo_match.groups()
        return {
            "type": "auth",
            "sub_type": "sudo",
            "source_ip": "127.0.0.1",
            "user": invoker,
            "action": f"Sudo execution as {target_user}: {cmd}",
            "raw": line_clean
        }

    return None


def analyze_security_logs(log_content: str) -> dict:
    """
    Process raw multi-line logs, parse entries, identify attack patterns,
    correlate events, and generate actionable detections.
    """
    lines = [line for line in log_content.splitlines() if line.strip()]
    parsed_entries = []
    failed_logins_by_ip = defaultdict(list)
    sqli_detections = []
    path_traversal_detections = []
    scanner_detections = []
    php2shell_detections = []

    for line in lines:
        # Try web log format
        web_record = parse_web_log_line(line)
        if web_record:
            parsed_entries.append(web_record)
            path = web_record["path"]
            raw_ua = web_record["user_agent"]
            ua = raw_ua.lower()

            # Check PHP2Shell RCE signatures (CVE-2026-109618 / CVE-2026-109619)
            if PHP2SHELL_UA_PATTERN.search(raw_ua) or PHP2SHELL_PAYLOAD_PATTERN.search(path):
                php2shell_detections.append({
                    "ip": web_record["source_ip"],
                    "path": path,
                    "ua": raw_ua,
                    "status": web_record["status_code"]
                })

            # Check SQL Injection
            for pattern in SQLI_PATTERNS:
                if pattern.search(path):
                    sqli_detections.append({
                        "ip": web_record["source_ip"],
                        "path": path,
                        "signature": pattern.pattern,
                        "status": web_record["status_code"]
                    })
                    break

            # Check Path Traversal
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.search(path):
                    path_traversal_detections.append({
                        "ip": web_record["source_ip"],
                        "path": path,
                        "signature": pattern.pattern
                    })
                    break

            # Check Automated Scanners
            for scanner in SCANNER_AGENTS:
                if scanner in ua:
                    scanner_detections.append({
                        "ip": web_record["source_ip"],
                        "tool": scanner,
                        "path": path
                    })
                    break
            continue

        # Try auth log format
        auth_record = parse_auth_log_line(line)
        if auth_record:
            parsed_entries.append(auth_record)
            if auth_record["sub_type"] == "ssh_failed":
                failed_logins_by_ip[auth_record["source_ip"]].append(auth_record["user"])
            continue

    # Correlation rules
    alerts = []

    # Rule 1: SSH Brute Force (> 3 failed attempts from same IP)
    for ip, users in failed_logins_by_ip.items():
        if len(users) >= 3:
            alerts.append({
                "severity": "High" if len(users) >= 5 else "Medium",
                "title": f"SSH Brute Force Attack Detected from {ip}",
                "category": "Unauthorized Access",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110 - Brute Force",
                "source_ip": ip,
                "description": f"Identified {len(users)} failed authentication attempts targeting users: {', '.join(set(users))}.",
                "recommendation": f"Add {ip} to firewall drop rules and enable Fail2Ban or IP rate limiting."
            })

    # Rule 2: SQL Injection
    if sqli_detections:
        ips = list({d["ip"] for d in sqli_detections})
        alerts.append({
            "severity": "Critical",
            "title": f"Web Application SQL Injection Exploitation from {', '.join(ips)}",
            "category": "Web Attack",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1190 - Exploit Public-Facing Application",
            "source_ip": ips[0] if ips else "Unknown",
            "description": f"Identified {len(sqli_detections)} distinct SQL injection query payloads in HTTP requests.",
            "recommendation": "Inspect backend database queries, implement parameterized prepared statements, and enforce WAF inspection."
        })

    # Rule 3: Path Traversal
    if path_traversal_detections:
        ips = list({d["ip"] for d in path_traversal_detections})
        alerts.append({
            "severity": "High",
            "title": f"Directory & Path Traversal Probe from {', '.join(ips)}",
            "category": "Web Attack",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1083 - File and Directory Discovery",
            "source_ip": ips[0] if ips else "Unknown",
            "description": f"Observed {len(path_traversal_detections)} directory traversal sequences aiming to access sensitive system files.",
            "recommendation": "Validate path sanitization in web server scripts and restrict read permissions on configuration paths."
        })

    # Rule 4: Security Scanner Recon
    if scanner_detections:
        tools = list({d["tool"] for d in scanner_detections})
        ips = list({d["ip"] for d in scanner_detections})
        alerts.append({
            "severity": "Medium",
            "title": f"Automated Vulnerability Scanner Activity ({', '.join(tools)})",
            "category": "Suspicious Activity",
            "mitre_tactic": "Reconnaissance",
            "mitre_technique": "T1595 - Active Scanning",
            "source_ip": ips[0] if ips else "Unknown",
            "description": f"Detected probing from offensive security tools: {', '.join(tools)}.",
            "recommendation": "Block scanner IP on perimeter security devices and check for any 200 OK responses to scanner endpoints."
        })

    # Rule 5: PHP2Shell RCE Exploit or Scanner Attempt (CVE-2026-109618 / CVE-2026-109619)
    if php2shell_detections:
        ips = list({d["ip"] for d in php2shell_detections})
        uas = list({d.get("ua") for d in php2shell_detections if d.get("ua")})
        alerts.append({
            "severity": "High",
            "title": f"Cloud WAF: PHP2Shell RCE Exploit or Scanner Attempt from {', '.join(ips)}",
            "category": "Web Attack",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1190 - Exploit Public-Facing Application",
            "source_ip": ips[0] if ips else "Unknown",
            "description": f"Identified {len(php2shell_detections)} requests matching PHP2Shell RCE exploit signatures or automated scanner toolings (CVE-2026-109618 / CVE-2026-109619). User-Agents: {', '.join(uas)}.",
            "recommendation": "Patch PHP runtime to remediate CVE-2026-109618. Apply WAF managed blocking rule for PHP2Shell probes and isolate target web server."
        })

    return {
        "total_lines_processed": len(lines),
        "total_parsed_entries": len(parsed_entries),
        "alerts_generated": alerts,
        "summary": {
            "failed_logins": sum(len(v) for v in failed_logins_by_ip.values()),
            "sqli_count": len(sqli_detections),
            "traversal_count": len(path_traversal_detections),
            "scanner_probes": len(scanner_detections),
            "php2shell_count": len(php2shell_detections)
        }
    }
