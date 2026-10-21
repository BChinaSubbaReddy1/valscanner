CREATE TABLE targets (
    id BIGINT NOT NULL AUTO_INCREMENT,
    name VARCHAR(150) NOT NULL,
    target_url VARCHAR(2048) NOT NULL,
    type VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    organization_id BIGINT NOT NULL,
    created_by_user_id BIGINT NOT NULL,
    decided_by_user_id BIGINT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    decision_reason VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_targets_organization_status (organization_id, status),
    CONSTRAINT fk_targets_organization FOREIGN KEY (organization_id) REFERENCES organizations (id),
    CONSTRAINT fk_targets_created_by FOREIGN KEY (created_by_user_id) REFERENCES users (id),
    CONSTRAINT fk_targets_decided_by FOREIGN KEY (decided_by_user_id) REFERENCES users (id)
);
