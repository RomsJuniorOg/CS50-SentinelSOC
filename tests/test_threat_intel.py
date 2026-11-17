"""
test_threat_intel.py - Unit tests for the Threat Intelligence and IOC scoring engine.
CS50 Final Project.
"""

from threat_intel import (
    identify_ioc_type,
    calculate_shannon_entropy,
    analyze_ioc
)


def test_identify_ioc_type_ipv4():
    assert identify_ioc_type("192.168.1.1") == "IPv4"
    assert identify_ioc_type("8.8.8.8") == "IPv4"
    assert identify_ioc_type("45.142.214.18") == "IPv4"


def test_identify_ioc_type_hashes():
    # 32 chars hex = MD5
    assert identify_ioc_type("e3b0c44298fc1c149afbf4c8996fb924") == "Hash_MD5"
    # 64 chars hex = SHA256
    assert identify_ioc_type("ed01ebf83334a1bfa188f3071f0947aa586c7da3cb7b58410e767d8e84a1e5d1") == "Hash_SHA256"


def test_identify_ioc_type_domains_and_urls():
    assert identify_ioc_type("malicious-c2.com") == "Domain"
    assert identify_ioc_type("http://example.com/payload.exe") == "URL"
    assert identify_ioc_type("https://phishing.site.top/login") == "URL"


def test_shannon_entropy():
    # Monotonous strings have very low entropy
    low_entropy = calculate_shannon_entropy("aaaaaaaaaa")
    assert low_entropy == 0.0

    # Random strings have higher entropy
    random_str = calculate_shannon_entropy("x8q9z2k1m4v7p")
    assert random_str > 3.0


def test_analyze_internal_ip():
    result = analyze_ioc("10.0.0.1")
    assert result["type"] == "IPv4"
    assert result["reputation"] == "Clean"
    assert result["details"]["is_private"] is True


def test_analyze_known_malicious_ip():
    result = analyze_ioc("45.142.214.18")
    assert result["type"] == "IPv4"
    assert result["reputation"] == "Malicious"
    assert result["threat_score"] >= 80


def test_analyze_known_malware_hash():
    # WannaCry SHA256
    result = analyze_ioc("ed01ebf83334a1bfa188f3071f0947aa586c7da3cb7b58410e767d8e84a1e5d1")
    assert result["type"] == "Hash_SHA256"
    assert result["reputation"] == "Malicious"
    assert result["threat_score"] == 100
    assert any("WannaCry" in factor for factor in result["risk_factors"])


def test_analyze_phishing_domain_with_suspicious_tld():
    result = analyze_ioc("login-bank-account-verification.top")
    assert result["type"] == "Domain"
    assert result["threat_score"] >= 40
    assert any("high-risk TLD" in factor for factor in result["risk_factors"])
