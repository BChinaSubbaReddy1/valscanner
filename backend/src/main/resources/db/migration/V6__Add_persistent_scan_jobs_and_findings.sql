CREATE TABLE scan_jobs (
    id BIGINT NOT NULL AUTO_INCREMENT,
    target_id BIGINT NOT NULL,
    organization_id BIGINT NOT NULL,
    requested_by_user_id BIGINT NOT NULL,
    scan_type VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    progress INT NOT NULL DEFAULT 0,
    status_message VARCHAR(250) NOT NULL,
    failure_reason VARCHAR(250) NULL,
    cancellation_requested BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME(6) NOT NULL,
    started_at DATETIME(6) NULL,
    completed_at DATETIME(6) NULL,
    PRIMARY KEY (id),
    KEY idx_scan_jobs_org_created (organization_id, created_at),
    KEY idx_scan_jobs_target (target_id),
    CONSTRAINT fk_scan_jobs_target FOREIGN KEY (target_id) REFERENCES targets (id),
    CONSTRAINT fk_scan_jobs_organization FOREIGN KEY (organization_id) REFERENCES organizations (id),
    CONSTRAINT fk_scan_jobs_requested_by FOREIGN KEY (requested_by_user_id) REFERENCES users (id)
);

CREATE TABLE scan_findings (
    id BIGINT NOT NULL AUTO_INCREMENT,
    scan_job_id BIGINT NOT NULL,
    check_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    affected_component VARCHAR(2048) NOT NULL,
    evidence VARCHAR(1000) NOT NULL,
    rationale VARCHAR(1000) NOT NULL,
    remediation VARCHAR(1000) NOT NULL,
    detection_source VARCHAR(64) NOT NULL,
    verification_status VARCHAR(32) NOT NULL,
    detected_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_scan_findings_scan (scan_job_id),
    CONSTRAINT fk_scan_findings_job FOREIGN KEY (scan_job_id) REFERENCES scan_jobs (id)
);
