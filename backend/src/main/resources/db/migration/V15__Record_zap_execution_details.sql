ALTER TABLE scan_jobs
    ADD COLUMN zap_requested BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN zap_failure_reason VARCHAR(250),
    ADD COLUMN zap_spider_status VARCHAR(24),
    ADD COLUMN zap_spider_discovered_count INTEGER,
    ADD COLUMN zap_passive_status VARCHAR(24),
    ADD COLUMN zap_alert_count INTEGER,
    ADD COLUMN zap_active_status VARCHAR(24);

UPDATE scan_jobs
SET zap_requested = TRUE
WHERE scan_type IN ('ZAP_PASSIVE', 'ZAP_ACTIVE');

UPDATE scan_jobs
SET zap_spider_status = 'COMPLETED',
    zap_passive_status = 'COMPLETED'
WHERE zap_engine_status = 'COMPLETED';

UPDATE scan_jobs
SET zap_active_status = 'COMPLETED'
WHERE scan_type = 'ZAP_ACTIVE'
  AND zap_engine_status = 'COMPLETED';
