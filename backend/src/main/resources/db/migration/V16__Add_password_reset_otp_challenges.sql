CREATE TABLE password_reset_challenges (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    otp_hash VARCHAR(100) NOT NULL,
    otp_expires_at DATETIME(6) NOT NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    resend_count INT NOT NULL DEFAULT 0,
    last_sent_at DATETIME(6) NOT NULL,
    verified_at DATETIME(6) NULL,
    reset_token_hash CHAR(64) NULL,
    reset_token_expires_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_password_reset_challenges_user (user_id),
    KEY idx_password_reset_challenges_reset_hash (reset_token_hash),
    CONSTRAINT fk_password_reset_challenges_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
