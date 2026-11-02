ALTER TABLE scan_findings
    ADD COLUMN endpoint_url VARCHAR(2048) NULL,
    ADD COLUMN http_method VARCHAR(10) NULL,
    ADD COLUMN parameter_name VARCHAR(255) NULL;
