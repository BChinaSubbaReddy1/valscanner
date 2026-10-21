ALTER TABLE organizations
    ADD COLUMN registration_admin_user_id BIGINT NULL,
    ADD UNIQUE KEY uk_org_registration_admin (registration_admin_user_id),
    ADD CONSTRAINT fk_org_registration_admin
        FOREIGN KEY (registration_admin_user_id) REFERENCES users (id);
