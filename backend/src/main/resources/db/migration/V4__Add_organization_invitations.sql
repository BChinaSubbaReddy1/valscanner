CREATE TABLE organization_invitations (
    id BIGINT NOT NULL AUTO_INCREMENT,
    organization_id BIGINT NOT NULL,
    created_by_user_id BIGINT NOT NULL,
    consumed_by_user_id BIGINT NULL,
    invited_email VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_org_invitations_token_hash (token_hash),
    KEY idx_org_invitations_org_email (organization_id, invited_email),
    CONSTRAINT fk_org_invitations_org FOREIGN KEY (organization_id) REFERENCES organizations (id),
    CONSTRAINT fk_org_invitations_creator FOREIGN KEY (created_by_user_id) REFERENCES users (id),
    CONSTRAINT fk_org_invitations_consumer FOREIGN KEY (consumed_by_user_id) REFERENCES users (id)
);
