ALTER TABLE scan_jobs
    ADD COLUMN reviewed_by_user_id BIGINT NULL,
    ADD COLUMN reviewed_at DATETIME(6) NULL,
    ADD COLUMN rejection_reason VARCHAR(1000) NULL,
    ADD KEY idx_scan_jobs_approval (organization_id, status, created_at),
    ADD CONSTRAINT fk_scan_jobs_reviewed_by
        FOREIGN KEY (reviewed_by_user_id) REFERENCES users (id);
