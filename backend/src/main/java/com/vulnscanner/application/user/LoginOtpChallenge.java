package com.vulnscanner.application.user;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "login_otp_challenges",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_login_otp_challenges_user", columnNames = "user_id"),
                @UniqueConstraint(name = "uk_login_otp_challenges_token_hash", columnNames = "challenge_token_hash")
        })
public class LoginOtpChallenge {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(name = "challenge_token_hash", length = 64, columnDefinition = "CHAR(64)")
    private String challengeTokenHash;

    @Column(name = "otp_hash", length = 100)
    private String otpHash;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    @Column(name = "send_count", nullable = false)
    private int sendCount;

    @Column(name = "resend_count", nullable = false)
    private int resendCount;

    @Column(name = "last_sent_at", nullable = false)
    private Instant lastSentAt;

    @Column(name = "rate_window_started_at", nullable = false)
    private Instant rateWindowStartedAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected LoginOtpChallenge() {
    }

    public LoginOtpChallenge(User user, String challengeTokenHash, String otpHash,
                             Instant expiresAt, Instant now) {
        this.user = user;
        this.challengeTokenHash = challengeTokenHash;
        this.otpHash = otpHash;
        this.expiresAt = expiresAt;
        this.lastSentAt = now;
        this.rateWindowStartedAt = now;
        this.createdAt = now;
        this.sendCount = 1;
    }

    public void startNewChallenge(String nextChallengeTokenHash, String nextOtpHash,
                                  Instant nextExpiry, Instant now) {
        challengeTokenHash = nextChallengeTokenHash;
        otpHash = nextOtpHash;
        expiresAt = nextExpiry;
        lastSentAt = now;
        consumedAt = null;
        resendCount = 0;
        sendCount++;
    }

    public void resend(String nextChallengeTokenHash, String nextOtpHash,
                       Instant nextExpiry, Instant now) {
        challengeTokenHash = nextChallengeTokenHash;
        otpHash = nextOtpHash;
        expiresAt = nextExpiry;
        lastSentAt = now;
        resendCount++;
        sendCount++;
        consumedAt = null;
    }

    public void recordFailedAttempt() {
        attemptCount++;
    }

    public void consume(Instant now) {
        challengeTokenHash = null;
        otpHash = null;
        expiresAt = null;
        consumedAt = now;
    }

    public void resetRateWindow(Instant now) {
        challengeTokenHash = null;
        otpHash = null;
        expiresAt = null;
        consumedAt = now;
        attemptCount = 0;
        sendCount = 0;
        resendCount = 0;
        rateWindowStartedAt = now;
    }

    public Long getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public String getChallengeTokenHash() {
        return challengeTokenHash;
    }

    public String getOtpHash() {
        return otpHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public int getAttemptCount() {
        return attemptCount;
    }

    public int getSendCount() {
        return sendCount;
    }

    public int getResendCount() {
        return resendCount;
    }

    public Instant getLastSentAt() {
        return lastSentAt;
    }

    public Instant getRateWindowStartedAt() {
        return rateWindowStartedAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }
}
