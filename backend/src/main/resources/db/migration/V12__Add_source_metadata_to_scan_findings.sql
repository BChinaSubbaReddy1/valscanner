ALTER TABLE scan_findings
    ADD COLUMN source_rule_id VARCHAR(64) NULL,
    ADD COLUMN source_confidence VARCHAR(16) NULL,
    ADD COLUMN source_reference VARCHAR(2048) NULL,
    ADD COLUMN source_cwe_id VARCHAR(16) NULL,
    ADD COLUMN source_wasc_id VARCHAR(16) NULL;
