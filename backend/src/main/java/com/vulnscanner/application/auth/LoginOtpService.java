package com.vulnscanner.application.auth;

import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.security.JwtService;
import com.vulnscanner.application.user.LoginOtpChallenge;
import com.vulnscanner.application.user.LoginOtpChallengeRepository;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.mail.MailException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;

@Service
public class LoginOtpService {
    private static final Logger LOG = LoggerFactory.getLogger(LoginOtpService.class);

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final LoginOtpChallengeRepository challengeRepository;
    private final PasswordResetEmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final PasswordResetRateLimiter rateLimiter;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Duration otpLifetime;
    private final Duration resendCooldown;
    private final Duration rateWindow;
    private final int maxAttempts;
    private final int maxResends;
    private final int maxSendsPerWindow;

    public LoginOtpService(AuthenticationManager authenticationManager,
                           UserRepository userRepository,
                           LoginOtpChallengeRepository challengeRepository,
                           PasswordResetEmailService emailService,
                           PasswordEncoder passwordEncoder,
                           JwtService jwtService,
                           PasswordResetRateLimiter rateLimiter,
                           Clock clock,
                           @Value("${app.auth.login-otp.expiration-seconds:300}") long expirationSeconds,
                           @Value("${app.auth.login-otp.resend-cooldown-seconds:60}") long resendCooldownSeconds,
                           @Value("${app.auth.login-otp.rate-window-seconds:900}") long rateWindowSeconds,
                           @Value("${app.auth.login-otp.max-attempts:5}") int maxAttempts,
                           @Value("${app.auth.login-otp.max-resends:3}") int maxResends,
                           @Value("${app.auth.login-otp.max-sends-per-window:5}") int maxSendsPerWindow) {
        if (expirationSeconds < 1 || resendCooldownSeconds < 1 || rateWindowSeconds < 1
                || maxAttempts < 1 || maxResends < 0 || maxSendsPerWindow < 1) {
            throw new IllegalArgumentException("Login OTP security settings must be positive");
        }
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.challengeRepository = challengeRepository;
        this.emailService = emailService;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.rateLimiter = rateLimiter;
        this.clock = clock;
        this.otpLifetime = Duration.ofSeconds(expirationSeconds);
        this.resendCooldown = Duration.ofSeconds(resendCooldownSeconds);
        this.rateWindow = Duration.ofSeconds(rateWindowSeconds);
        this.maxAttempts = maxAttempts;
        this.maxResends = maxResends;
        this.maxSendsPerWindow = maxSendsPerWindow;
    }

    @Transactional
    public LoginOtpChallengeResponse startLogin(LoginRequest request, String remoteAddress) {
        acquireRateLimit(remoteAddress);
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, request.password()));
        } catch (AuthenticationException authenticationFailure) {
            throw new BadCredentialsException("Invalid email or password");
        }

        User user = userRepository.findByEmailIgnoreCaseForUpdate(email)
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));
        ensureEligible(user);
        if (!emailService.isConfigured()) {
            throw new IllegalStateException("Login verification email is temporarily unavailable; contact support.");
        }

        Instant now = clock.instant();
        LoginOtpChallenge challenge = challengeRepository.findByUserIdForUpdate(user.getId()).orElse(null);
        if (challenge == null) {
            String challengeToken = generateChallengeToken();
            String otp = generateOtp();
            challenge = new LoginOtpChallenge(user, sha256(challengeToken), passwordEncoder.encode(otp),
                    now.plus(otpLifetime), now);
            sendOtp(user.getEmail(), otp);
            challengeRepository.save(challenge);
            return response(challengeToken, user, now);
        } else {
            prepareRateWindow(challenge, now);
            ensureCanSend(challenge, now);
            String otp = generateOtp();
            String challengeToken = generateChallengeToken();
            challenge.startNewChallenge(sha256(challengeToken), passwordEncoder.encode(otp),
                    now.plus(otpLifetime), now);
            sendOtp(user.getEmail(), otp);
            challengeRepository.save(challenge);
            return response(challengeToken, user, now);
        }
    }

    @Transactional
    public Optional<LoginResponse> verify(LoginOtpVerificationRequest request, String remoteAddress) {
        String tokenHash = sha256(request.challengeToken());
        Optional<LoginOtpChallenge> candidate = challengeRepository.findByChallengeTokenHash(tokenHash);
        if (candidate.isEmpty()) {
            return Optional.empty();
        }
        if (!rateLimiter.tryAcquireLoginOtpVerification(tokenHash)) {
            throw new RateLimitExceededException();
        }

        Long userId = candidate.get().getUser().getId();
        Optional<User> lockedUser = userRepository.findByIdForUpdate(userId);
        Optional<LoginOtpChallenge> lockedChallenge = challengeRepository.findByUserIdForUpdate(userId);
        if (lockedUser.isEmpty() || lockedChallenge.isEmpty()) {
            return Optional.empty();
        }

        User user = lockedUser.get();
        LoginOtpChallenge challenge = lockedChallenge.get();
        Instant now = clock.instant();
        if (!tokenHash.equals(challenge.getChallengeTokenHash())
                || challenge.getConsumedAt() != null
                || challenge.getOtpHash() == null
                || challenge.getExpiresAt() == null
                || !now.isBefore(challenge.getExpiresAt())
                || challenge.getAttemptCount() >= maxAttempts) {
            if (tokenHash.equals(challenge.getChallengeTokenHash())) {
                challenge.consume(now);
                challengeRepository.save(challenge);
            }
            return Optional.empty();
        }

        if (!passwordEncoder.matches(request.otp(), challenge.getOtpHash())) {
            challenge.recordFailedAttempt();
            if (challenge.getAttemptCount() >= maxAttempts) {
                challenge.consume(now);
            }
            challengeRepository.save(challenge);
            return Optional.empty();
        }

        if (!isEligible(user)) {
            challenge.consume(now);
            challengeRepository.save(challenge);
            return Optional.empty();
        }

        challenge.consume(now);
        challengeRepository.save(challenge);
        String token = jwtService.generateToken(user);
        return Optional.of(new LoginResponse(token, "Bearer", user.getId(), user.getEmail(),
                user.getRoles().stream()
                        .filter(role -> role.getName() != RoleName.CUSTOMER)
                        .map(role -> role.getName().name())
                        .toList()));
    }

    @Transactional
    public Optional<LoginOtpChallengeResponse> resend(LoginOtpResendRequest request, String remoteAddress) {
        String tokenHash = sha256(request.challengeToken());
        Optional<LoginOtpChallenge> candidate = challengeRepository.findByChallengeTokenHash(tokenHash);
        if (candidate.isEmpty()) {
            return Optional.empty();
        }
        if (!rateLimiter.tryAcquireLoginOtpResend(tokenHash)) {
            throw new RateLimitExceededException();
        }
        Long userId = candidate.get().getUser().getId();
        Optional<User> lockedUser = userRepository.findByIdForUpdate(userId);
        Optional<LoginOtpChallenge> currentChallenge = challengeRepository.findByUserIdForUpdate(userId);
        if (lockedUser.isEmpty() || currentChallenge.isEmpty()) {
            return Optional.empty();
        }

        User user = lockedUser.get();
        LoginOtpChallenge challenge = currentChallenge.get();
        Instant now = clock.instant();
        if (!tokenHash.equals(challenge.getChallengeTokenHash())
                || challenge.getConsumedAt() != null
                || challenge.getExpiresAt() == null
                || !now.isBefore(challenge.getExpiresAt())
                || challenge.getAttemptCount() >= maxAttempts
                || challenge.getResendCount() >= maxResends
                || now.isBefore(challenge.getLastSentAt().plus(resendCooldown))
                || !isEligible(user)
                || !emailService.isConfigured()) {
            return Optional.empty();
        }
        prepareRateWindow(challenge, now);
        if (challenge.getConsumedAt() != null || challenge.getSendCount() >= maxSendsPerWindow) {
            return Optional.empty();
        }

        String otp = generateOtp();
        String nextChallengeToken = generateChallengeToken();
        challenge.resend(sha256(nextChallengeToken), passwordEncoder.encode(otp), now.plus(otpLifetime), now);
        sendOtp(user.getEmail(), otp);
        challengeRepository.save(challenge);
        return Optional.of(response(nextChallengeToken, user, now));
    }

    private LoginOtpChallengeResponse response(String challengeToken, User user, Instant now) {
        return new LoginOtpChallengeResponse(challengeToken, maskEmail(user.getEmail()),
                now.plus(otpLifetime), now.plus(resendCooldown));
    }

    private void prepareRateWindow(LoginOtpChallenge challenge, Instant now) {
        if (!now.isBefore(challenge.getRateWindowStartedAt().plus(rateWindow))) {
            challenge.resetRateWindow(now);
        }
    }

    private void ensureCanSend(LoginOtpChallenge challenge, Instant now) {
        if (challenge.getSendCount() >= maxSendsPerWindow
                || challenge.getAttemptCount() >= maxAttempts
                || (challenge.getConsumedAt() == null && challenge.getExpiresAt() != null
                    && now.isBefore(challenge.getExpiresAt())
                    && now.isBefore(challenge.getLastSentAt().plus(resendCooldown)))) {
            throw new IllegalStateException("Login verification is invalid, expired, or temporarily unavailable.");
        }
    }

    private void ensureEligible(User user) {
        if (!isEligible(user)) {
            throw new BadCredentialsException("Invalid email or password");
        }
    }

    private boolean isEligible(User user) {
        if (user.getStatus() != UserStatus.ACTIVE
                || user.getRoles().stream().noneMatch(role -> role.getName() != RoleName.CUSTOMER)) {
            return false;
        }
        return user.getOrganization() == null
                || user.getOrganization().getStatus() == OrganizationStatus.APPROVED;
    }

    private void acquireRateLimit(String remoteAddress) {
        if (!rateLimiter.tryAcquireLoginOtp(remoteAddress)) {
            throw new RateLimitExceededException();
        }
    }

    private void sendOtp(String email, String otp) {
        try {
            emailService.sendLoginOtp(email, otp, otpLifetime);
        } catch (MailException | IllegalStateException deliveryFailure) {
            LOG.warn("Login verification email delivery failed");
            throw new IllegalStateException(
                    "Login verification email is temporarily unavailable; contact support.");
        }
    }

    private String generateOtp() {
        return String.format(Locale.ROOT, "%06d", secureRandom.nextInt(1_000_000));
    }

    private String generateChallengeToken() {
        byte[] token = new byte[32];
        secureRandom.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    private String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private String maskEmail(String email) {
        int separator = email.indexOf('@');
        if (separator <= 0) {
            return "***";
        }
        String localPart = email.substring(0, separator);
        String visible = localPart.length() == 1 ? "*" : localPart.substring(0, 1) + "***";
        return visible + email.substring(separator);
    }
}
