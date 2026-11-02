package com.vulnscanner.application.user;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "password_reset_challenges",
        uniqueConstraints = @UniqueConstraint(name = "uk_password_reset_challenges_user", columnNames = "user_id"),
        indexes = @Index(name = "idx_password_reset_challenges_reset_hash", columnList = "reset_token_hash"))
public class PasswordResetChallenge {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(name = "otp_hash", nullable = false, length = 100)
    private String otpHash;

    @Column(name = "otp_expires_at", nullable = false)
    private Instant otpExpiresAt;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    @Column(name = "resend_count", nullable = false)
    private int resendCount;

    @Column(name = "last_sent_at", nullable = false)
    private Instant lastSentAt;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @Column(name = "reset_token_hash", length = 64, columnDefinition = "CHAR(64)")
    private String resetTokenHash;

    @Column(name = "reset_token_expires_at")
    private Instant resetTokenExpiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    protected PasswordResetChallenge() {
    }

    public PasswordResetChallenge(User user, String otpHash, Instant otpExpiresAt, Instant now) {
        this.user = user;
        this.otpHash = otpHash;
        this.otpExpiresAt = otpExpiresAt;
        this.lastSentAt = now;
        this.createdAt = now;
    }

    public void resend(String nextOtpHash, Instant nextExpiry, Instant now) {
        otpHash = nextOtpHash;
        otpExpiresAt = nextExpiry;
        lastSentAt = now;
        resendCount++;
        attemptCount = 0;
        verifiedAt = null;
        resetTokenHash = null;
        resetTokenExpiresAt = null;
    }

    public void recordFailedAttempt() {
        attemptCount++;
    }

    public void verify(String tokenHash, Instant tokenExpiresAt, Instant now) {
        verifiedAt = now;
        resetTokenHash = tokenHash;
        resetTokenExpiresAt = tokenExpiresAt;
    }

    public Long getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public String getOtpHash() {
        return otpHash;
    }

    public Instant getOtpExpiresAt() {
        return otpExpiresAt;
    }

    public int getAttemptCount() {
        return attemptCount;
    }

    public int getResendCount() {
        return resendCount;
    }

    public Instant getLastSentAt() {
        return lastSentAt;
    }

    public Instant getVerifiedAt() {
        return verifiedAt;
    }

    public String getResetTokenHash() {
        return resetTokenHash;
    }

    public Instant getResetTokenExpiresAt() {
        return resetTokenExpiresAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
