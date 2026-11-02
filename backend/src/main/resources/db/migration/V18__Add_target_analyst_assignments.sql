CREATE TABLE target_analyst_assignments (
    id BIGINT NOT NULL AUTO_INCREMENT,
    target_id BIGINT NOT NULL,
    analyst_user_id BIGINT NOT NULL,
    assigned_by_user_id BIGINT NOT NULL,
    assigned_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_target_analyst_assignment (target_id, analyst_user_id),
    KEY idx_target_assignments_analyst (analyst_user_id),
    CONSTRAINT fk_target_assignment_target FOREIGN KEY (target_id) REFERENCES targets (id),
    CONSTRAINT fk_target_assignment_analyst FOREIGN KEY (analyst_user_id) REFERENCES users (id),
    CONSTRAINT fk_target_assignment_assigned_by FOREIGN KEY (assigned_by_user_id) REFERENCES users (id)
);
