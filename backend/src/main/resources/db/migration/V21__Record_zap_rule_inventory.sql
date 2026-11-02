ALTER TABLE scan_jobs
    ADD COLUMN zap_rule_inventory_status VARCHAR(24) NOT NULL DEFAULT 'NOT_CAPTURED',
    ADD COLUMN zap_passive_enabled_rules TEXT NULL,
    ADD COLUMN zap_active_enabled_rules TEXT NULL;
