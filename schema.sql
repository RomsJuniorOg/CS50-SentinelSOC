-- SentinelSOC Database Schema
-- CS50 Final Project

DROP TABLE IF EXISTS activity_logs;
DROP TABLE IF EXISTS incident_timeline;
DROP TABLE IF EXISTS iocs;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS users;

-- Analysts and administrators
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    full_name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security incidents
CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'Investigating', 'Mitigated', 'Closed')),
    category TEXT NOT NULL CHECK(category IN ('Malware', 'Phishing', 'Unauthorized Access', 'Web Attack', 'Denial of Service', 'Data Exfiltration', 'Suspicious Activity')),
    mitre_tactic TEXT DEFAULT 'Initial Access',
    mitre_technique TEXT DEFAULT 'T1078 - Valid Accounts',
    affected_asset TEXT NOT NULL,
    assigned_to INTEGER,
    created_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
);

-- Indicators of Compromise (IOCs)
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    ioc_type TEXT NOT NULL CHECK(ioc_type IN ('IPv4', 'Domain', 'URL', 'Hash_MD5', 'Hash_SHA256')),
    value TEXT NOT NULL,
    threat_score INTEGER NOT NULL DEFAULT 0,
    reputation TEXT NOT NULL DEFAULT 'Clean' CHECK(reputation IN ('Clean', 'Suspicious', 'Malicious')),
    enrichment_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

-- Incident timeline & investigation logs
CREATE TABLE incident_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    user_id INTEGER,
    entry_type TEXT NOT NULL DEFAULT 'Note' CHECK(entry_type IN ('Created', 'Status Change', 'Severity Change', 'Note', 'IOC Added')),
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Platform audit logs
CREATE TABLE activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    ip_address TEXT DEFAULT '127.0.0.1',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Indexes for performance
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_category ON incidents(category);
CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_iocs_incident ON iocs(incident_id);
CREATE INDEX idx_timeline_incident ON incident_timeline(incident_id);
