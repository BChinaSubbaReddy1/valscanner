CREATE TABLE login_otp_challenges (
    id BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    challenge_token_hash CHAR(64) NULL,
    otp_hash VARCHAR(100) NULL,
    expires_at DATETIME(6) NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    send_count INT NOT NULL DEFAULT 0,
    resend_count INT NOT NULL DEFAULT 0,
    last_sent_at DATETIME(6) NOT NULL,
    rate_window_started_at DATETIME(6) NOT NULL,
    consumed_at DATETIME(6) NULL,
    created_at DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_login_otp_challenges_user (user_id),
    UNIQUE KEY uk_login_otp_challenges_token_hash (challenge_token_hash),
    CONSTRAINT fk_login_otp_challenges_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
