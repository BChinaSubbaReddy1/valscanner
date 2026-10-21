CREATE TABLE scan_crawl_pages (
    id BIGINT NOT NULL AUTO_INCREMENT,
    scan_job_id BIGINT NOT NULL,
    url VARCHAR(2048) NOT NULL,
    url_hash VARCHAR(64) NOT NULL,
    depth INT NOT NULL,
    status_code INT NOT NULL,
    response_bytes INT NOT NULL,
    discovered_links INT NOT NULL,
    discovered_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_scan_crawl_pages_url_hash (scan_job_id, url_hash),
    KEY idx_scan_crawl_pages_scan (scan_job_id),
    CONSTRAINT fk_scan_crawl_pages_job FOREIGN KEY (scan_job_id) REFERENCES scan_jobs (id)
);
