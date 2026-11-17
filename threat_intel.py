"""
threat_intel.py - Threat Intelligence Enrichment and IOC Scoring Engine.
CS50 Final Project.
"""

import math
import re
import ipaddress
from urllib.parse import urlparse

# Built-in Threat Intelligence Signatures (Known C2, malware, ransomware samples)
KNOWN_MALICIOUS_HASHES = {
    # WannaCry Ransomware (SHA256)
    "ed01ebf83334a1bfa188f3071f0947aa586c7da3cb7b58410e767d8e84a1e5d1": {
        "family": "WannaCry",
        "category": "Ransomware",
        "severity": 100,
        "notes": "Known WannaCry SMB Worm component."
    },
    # Mimikatz credential dumper (SHA256)
    "a14db288b8efcbb9d06b3a0bcf4890fb916a03767cb4a26e843e91122e25d2be": {
        "family": "Mimikatz",
        "category": "Credential Dumping",
        "severity": 95,
        "notes": "Post-exploitation credential extraction binary."
    },
    # Cobalt Strike Beacon (MD5)
    "e3b0c44298fc1c149afbf4c8996fb924": {
        "family": "Cobalt Strike",
        "category": "Command & Control",
        "severity": 90,
        "notes": "Staged Cobalt Strike Beacon payload."
    },
    # Emotet Dropper (SHA256)
    "5f4dcc3b5aa765d61d8327deb882cf992b9699aaf590116155bf730f929d9ec0": {
        "family": "Emotet",
        "category": "Banking Trojan / Botnet",
        "severity": 95,
        "notes": "High-velocity modular infostealer & loader."
    }
}

KNOWN_MALICIOUS_IPS = {
    "185.220.101.5": {"actor": "Tor Exit Node", "score": 85, "reason": "Anonymous Tor relay associated with brute-force attacks."},
    "194.26.29.112": {"actor": "Bulletproof Hosting", "score": 92, "reason": "Identified C2 server for LockBit affiliates."},
    "45.142.214.18": {"actor": "Cobalt Strike TeamServer", "score": 98, "reason": "Active staging host for lateral movement."},
    "103.151.125.9": {"actor": "Phishing Proxy", "score": 88, "reason": "Reverse-proxy used in MFA-bypass phishing campaigns."}
}

KNOWN_MALICIOUS_DOMAINS = {
    "login-microsoft-auth-verify.com": {"category": "Phishing", "score": 95, "notes": "Credential harvesting portal targeting M365."},
    "payload-delivery-cdn77.net": {"category": "Malware C2", "score": 90, "notes": "Known staging domain for second-stage payloads."},
    "update-windows-service.xyz": {"category": "Trojanized Installer", "score": 88, "notes": "Typosquatting Windows update masquerade."},
    "c2-beacon-tunnel.top": {"category": "Command & Control", "score": 92, "notes": "Encrypted C2 DNS tunneling channel."}
}

SUSPICIOUS_TLDS = {".top", ".xyz", ".click", ".work", ".buzz", ".monster", ".gq", ".ml", ".cf"}


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy in domain names often indicates DGA (Domain Generation Algorithms)
    or encrypted exfiltration tunnels.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def identify_ioc_type(value: str) -> str:
    """
    Classify an observable string into its IOC type:
    IPv4, Domain, URL, Hash_MD5, Hash_SHA256, or 'Unknown'.
    """
    clean_val = value.strip()

    # MD5 (32 hex characters)
    if re.fullmatch(r"^[a-fA-F0-9]{32}$", clean_val):
        return "Hash_MD5"

    # SHA256 (64 hex characters)
    if re.fullmatch(r"^[a-fA-F0-9]{64}$", clean_val):
        return "Hash_SHA256"

    # IPv4 address
    try:
        ip = ipaddress.IPv4Address(clean_val)
        return "IPv4"
    except ipaddress.AddressValueError:
        pass

    # URL
    if clean_val.startswith("http://") or clean_val.startswith("https://"):
        return "URL"

    # Domain name
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.fullmatch(domain_pattern, clean_val):
        return "Domain"

    return "Unknown"


def analyze_ioc(value: str) -> dict:
    """
    Comprehensive Threat Intelligence analysis of an Indicator of Compromise.
    Returns calculated threat score (0-100), reputation label, risk factors, and remediation advice.
    """
    clean_val = value.strip()
    ioc_type = identify_ioc_type(clean_val)

    result = {
        "value": clean_val,
        "type": ioc_type,
        "threat_score": 0,
        "reputation": "Clean",
        "risk_factors": [],
        "recommendation": "No action needed. Observable appears clean.",
        "details": {}
    }

    if ioc_type == "Unknown":
        result["reputation"] = "Suspicious"
        result["threat_score"] = 25
        result["risk_factors"].append("Format does not match standard RFC IOC types.")
        result["recommendation"] = "Verify observable format."
        return result

    # --- IPv4 ANALYSIS ---
    if ioc_type == "IPv4":
        ip = ipaddress.IPv4Address(clean_val)
        is_private = ip.is_private or ip.is_loopback or ip.is_link_local
        result["details"]["is_private"] = is_private
        result["details"]["is_multicast"] = ip.is_multicast

        if is_private:
            result["threat_score"] = 10
            result["reputation"] = "Clean"
            result["risk_factors"].append("RFC1918 / Loopback Internal IP Address.")
            result["recommendation"] = "Internal asset. Investigate lateral movement locally if unexpected."
            return result

        # Check known signature database
        if clean_val in KNOWN_MALICIOUS_IPS:
            match = KNOWN_MALICIOUS_IPS[clean_val]
            result["threat_score"] = match["score"]
            result["reputation"] = "Malicious"
            result["risk_factors"].append(f"Threat Intelligence Feed match: {match['actor']}")
            result["risk_factors"].append(match["reason"])
            result["recommendation"] = "Immediate containment: Block IP on perimeter firewalls and inspect active sessions."
            return result

        # Heuristic scoring for external IPs
        score = 20
        # If in high-risk netblocks (simulated heuristic)
        if clean_val.startswith("185.") or clean_val.startswith("194.") or clean_val.startswith("45."):
            score += 25
            result["risk_factors"].append("Originates from ASNs with elevated abuse and bulletproof hosting reports.")
        result["threat_score"] = score
        result["reputation"] = "Suspicious" if score >= 40 else "Clean"
        result["recommendation"] = "Monitor outbound connections and query firewall logs."

    # --- DOMAIN ANALYSIS ---
    elif ioc_type == "Domain":
        domain_lower = clean_val.lower()
        entropy = calculate_shannon_entropy(domain_lower)
        result["details"]["entropy"] = entropy

        if domain_lower in KNOWN_MALICIOUS_DOMAINS:
            match = KNOWN_MALICIOUS_DOMAINS[domain_lower]
            result["threat_score"] = match["score"]
            result["reputation"] = "Malicious"
            result["risk_factors"].append(f"Threat Feed match: {match['category']}")
            result["risk_factors"].append(match["notes"])
            result["recommendation"] = "Sinkhole domain on internal DNS and block outbound proxy connections."
            return result

        score = 15
        # Check suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                score += 35
                result["risk_factors"].append(f"Utilizes high-risk TLD ({tld}) commonly leveraged in disposable phishing/C2.")
                break

        # Check DGA / High entropy
        if entropy > 3.6:
            score += 40
            result["risk_factors"].append(f"Elevated Shannon entropy ({entropy}) strongly indicates algorithmic DGA generation.")

        # Keywords in domain
        suspicious_keywords = ["login", "verify", "secure", "update", "bank", "portal", "token", "auth", "account"]
        for kw in suspicious_keywords:
            if kw in domain_lower and not ("microsoft.com" in domain_lower or "google.com" in domain_lower):
                score += 20
                result["risk_factors"].append(f"Contains credential harvesting keyword ('{kw}').")
                break

        result["threat_score"] = min(100, score)
        if result["threat_score"] >= 70:
            result["reputation"] = "Malicious"
            result["recommendation"] = "Block domain across DNS Resolvers and Secure Web Gateway."
        elif result["threat_score"] >= 40:
            result["reputation"] = "Suspicious"
            result["recommendation"] = "Conduct DNS query log review to identify queried endpoints."
        else:
            result["reputation"] = "Clean"
            result["recommendation"] = "Standard monitoring."

    # --- URL ANALYSIS ---
    elif ioc_type == "URL":
        parsed = urlparse(clean_val)
        hostname = parsed.hostname or ""
        score = 25
        result["details"]["hostname"] = hostname

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            score += 35
            result["risk_factors"].append("Raw IP address used in host portion instead of registered FQDN.")

        if any(ext in parsed.path.lower() for ext in [".exe", ".scr", ".ps1", ".vbs", ".bat", ".elf"]):
            score += 40
            result["risk_factors"].append("Path directly references executable/script payload delivery.")

        if "base64" in clean_val.lower() or "cmd=" in clean_val.lower() or "eval(" in clean_val.lower():
            score += 35
            result["risk_factors"].append("URL parameters contain web shell / arbitrary code execution signatures.")

        result["threat_score"] = min(100, score)
        result["reputation"] = "Malicious" if result["threat_score"] >= 70 else ("Suspicious" if result["threat_score"] >= 40 else "Clean")
        result["recommendation"] = "Block URL in perimeter proxies and reset sessions to this destination."

    # --- HASH ANALYSIS (MD5 / SHA256) ---
    elif ioc_type in ("Hash_MD5", "Hash_SHA256"):
        hash_lower = clean_val.lower()
        if hash_lower in KNOWN_MALICIOUS_HASHES:
            match = KNOWN_MALICIOUS_HASHES[hash_lower]
            result["threat_score"] = match["severity"]
            result["reputation"] = "Malicious"
            result["risk_factors"].append(f"Known Malware Signature: {match['family']} ({match['category']})")
            result["risk_factors"].append(match["notes"])
            result["recommendation"] = "Isolate infected endpoint immediately, trigger EDR quarantine, and sweep network."
            return result

        result["threat_score"] = 20
        result["reputation"] = "Clean"
        result["recommendation"] = "Hash not observed in public threat database. Submit to sandboxing if behavioral flags exist."

    return result
