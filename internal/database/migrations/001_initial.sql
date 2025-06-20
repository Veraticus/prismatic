-- Initial schema for Prismatic database

CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aws_profile TEXT,
    aws_regions TEXT, -- JSON array
    kube_context TEXT,
    scanners INTEGER, -- Bitmask of enabled scanners
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT CHECK(status IN ('running', 'completed', 'failed')),
    error_details TEXT
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    scanner TEXT,
    severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    title TEXT,
    description TEXT,
    resource TEXT,
    technical_details TEXT, -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER REFERENCES findings(id),
    reason TEXT,
    suppressed_by TEXT,
    suppressed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_suppressions_finding ON suppressions(finding_id);