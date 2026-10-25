ALTER TABLE scan_jobs
    ADD COLUMN native_engine_status VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN zap_engine_status VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN discovered_page_count INT NULL,
    ADD COLUMN visited_page_count INT NULL,
    ADD COLUMN tested_passive_page_count INT NULL;
