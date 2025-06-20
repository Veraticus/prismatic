-- Migration to support full storage in database instead of files

-- Raw scanner outputs
CREATE TABLE scanner_outputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    scanner TEXT NOT NULL,
    raw_output TEXT NOT NULL, -- JSON or raw text output from scanner
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Enrichments for findings
CREATE TABLE finding_enrichments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL, -- Finding ID (hash-based, not FK to findings table)
    scan_id INTEGER REFERENCES scans(id),
    business_impact TEXT,
    remediation_steps TEXT,
    risk_score INTEGER,
    estimated_effort TEXT,
    ai_analysis TEXT, -- JSON with detailed AI analysis
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan metadata and configuration
CREATE TABLE scan_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id) UNIQUE,
    client_name TEXT,
    environment TEXT,
    configuration TEXT, -- JSON configuration that was used
    summary TEXT, -- JSON scan summary
    scanner_versions TEXT, -- JSON with scanner version info
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan logs for human-readable output
CREATE TABLE scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    log_level TEXT CHECK(log_level IN ('DEBUG', 'INFO', 'WARN', 'ERROR')),
    message TEXT,
    scanner TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Progress tracking for real-time updates
CREATE TABLE scan_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    scanner TEXT,
    status TEXT CHECK(status IN ('pending', 'running', 'completed', 'failed')),
    progress_percent INTEGER DEFAULT 0,
    current_step TEXT,
    error_message TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_scanner_outputs_scan ON scanner_outputs(scan_id);
CREATE INDEX idx_finding_enrichments_scan ON finding_enrichments(scan_id);
CREATE INDEX idx_finding_enrichments_finding ON finding_enrichments(finding_id);
CREATE INDEX idx_scan_logs_scan ON scan_logs(scan_id);
CREATE INDEX idx_scan_progress_scan ON scan_progress(scan_id);
CREATE UNIQUE INDEX idx_scan_metadata_scan ON scan_metadata(scan_id);
CREATE UNIQUE INDEX idx_scan_progress_scanner ON scan_progress(scan_id, scanner);