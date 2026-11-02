package com.vulnscanner.application.auth;

import com.vulnscanner.application.audit.AuditEvent;
import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.security.JwtService;
import com.vulnscanner.application.user.PasswordResetChallenge;
import com.vulnscanner.application.user.PasswordResetChallengeRepository;
import com.vulnscanner.application.user.PasswordResetTokenRepository;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
import java.util.Set;

@Service
public class AuthService {
    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);
    private static final Duration OTP_LIFETIME = Duration.ofMinutes(10);
    private static final Duration RESET_TOKEN_LIFETIME = Duration.ofMinutes(15);
    private static final Duration RESEND_COOLDOWN = Duration.ofSeconds(60);
    private static final Duration RESEND_WINDOW = Duration.ofHours(1);
    private static final int MAX_OTP_ATTEMPTS = 5;
    private static final int MAX_RESENDS = 3;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final OrganizationRepository organizationRepository;
    private final AuditEventRepository auditEventRepository;
    private final JwtService jwtService;
    private final PasswordResetChallengeRepository passwordResetChallengeRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordResetEmailService passwordResetEmailService;
    private final PasswordResetRateLimiter passwordResetRateLimiter;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       RoleRepository roleRepository,
                       OrganizationRepository organizationRepository,
                       AuditEventRepository auditEventRepository,
                       JwtService jwtService,
                       PasswordResetChallengeRepository passwordResetChallengeRepository,
                       PasswordResetTokenRepository passwordResetTokenRepository,
                       PasswordResetEmailService passwordResetEmailService,
                       PasswordResetRateLimiter passwordResetRateLimiter,
                       Clock clock) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.organizationRepository = organizationRepository;
        this.auditEventRepository = auditEventRepository;
        this.jwtService = jwtService;
        this.passwordResetChallengeRepository = passwordResetChallengeRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.passwordResetEmailService = passwordResetEmailService;
        this.passwordResetRateLimiter = passwordResetRateLimiter;
        this.clock = clock;
    }

    public void logout(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwtService.invalidateToken(authHeader.substring(7));
        }
    }

    @Transactional
    public User register(RegisterRequest request) {
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already registered");
        }
        RoleName requestedRole;
        try {
            requestedRole = request.role() == null || request.role().isBlank()
                    ? RoleName.SECURITY_ANALYST
                    : RoleName.valueOf(request.role().trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException invalidRole) {
            throw new IllegalArgumentException("Unsupported registration role");
        }
        if (requestedRole != RoleName.ADMIN && requestedRole != RoleName.SECURITY_ANALYST) {
            throw new IllegalArgumentException("Public registration cannot assign this role");
        }

        User user = new User();
        user.setFirstName(request.firstName().trim());
        user.setLastName(request.lastName().trim());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setStatus(UserStatus.PENDING_APPROVAL);
        user.setRoles(Set.of(roleRepository.findByName(requestedRole)
                .orElseThrow(() -> new IllegalStateException(requestedRole + " role missing"))));

        Organization organization;
        if (requestedRole == RoleName.ADMIN) {
            if (request.organizationName() == null || request.organizationName().isBlank()) {
                throw new IllegalArgumentException("Organization Admin registration requires an organization name");
            }
            if (!organizationRepository.findAllByNormalizedName(request.organizationName().trim()).isEmpty()) {
                throw new IllegalArgumentException("Organization already exists");
            }
            organization = new Organization();
            organization.setName(request.organizationName().trim());
            organization.setContactEmail(request.organizationContactEmail() == null ||
                    request.organizationContactEmail().isBlank() ? email :
                    request.organizationContactEmail().trim().toLowerCase(Locale.ROOT));
            organization.setPrimaryContactName(user.getFirstName() + " " + user.getLastName());
            organization.setStatus(OrganizationStatus.PENDING);
            organization = organizationRepository.save(organization);
        } else {
            if (request.organizationName() == null || request.organizationName().isBlank() ||
                    request.organizationContactEmail() != null) {
                throw new IllegalArgumentException("Security Analyst registration requires an organization name");
            }
            var matchingOrganizations = organizationRepository.findAllByNormalizedName(
                    request.organizationName().trim());
            if (matchingOrganizations.isEmpty()) {
                throw new IllegalArgumentException("No organization matches the supplied name");
            }
            if (matchingOrganizations.size() > 1) {
                throw new IllegalArgumentException("Organization name is ambiguous; contact support");
            }
            organization = matchingOrganizations.getFirst();
            if (organization.getStatus() != OrganizationStatus.APPROVED) {
                throw new IllegalArgumentException("The requested organization is not approved");
            }
        }
        user.setOrganization(organization);
        User saved = userRepository.save(user);
        if (requestedRole == RoleName.ADMIN) {
            organization.setRegistrationAdmin(saved);
            organizationRepository.save(organization);
        }
        AuditEvent event = new AuditEvent();
        event.setEventType(requestedRole == RoleName.ADMIN
                ? "ORGANIZATION_ADMIN_REGISTRATION_SUBMITTED"
                : "ORGANIZATION_MEMBERSHIP_REQUESTED");
        event.setEventLevel("INFO");
        event.setOrganization(organization);
        event.setTargetUser(saved);
        event.setActor(saved);
        event.setMessage("Pending " + requestedRole + " registration submitted for " + saved.getEmail());
        auditEventRepository.save(event);
        return saved;
    }

    @Transactional
    public void requestPasswordReset(ForgotPasswordRequest request, String remoteAddress) {
        if (!passwordResetRateLimiter.tryAcquirePasswordReset(remoteAddress)) {
            throw new RateLimitExceededException();
        }
        if (!passwordResetEmailService.isConfigured()) {
            LOG.warn("Password reset email is not configured");
            throw new IllegalStateException("Password reset email is temporarily unavailable; contact support.");
        }

        String email = request.email().trim().toLowerCase(Locale.ROOT);
        Optional<User> matchingUser = userRepository.findByEmailIgnoreCaseForUpdate(email);
        if (matchingUser.isEmpty()) {
            return;
        }

        User user = matchingUser.get();
        Instant now = clock.instant();
        Optional<PasswordResetChallenge> currentChallenge =
                passwordResetChallengeRepository.findByUserIdForUpdate(user.getId());
        PasswordResetChallenge challenge;
        if (currentChallenge.isPresent()
                && now.isBefore(currentChallenge.get().getCreatedAt().plus(RESEND_WINDOW))) {
            challenge = currentChallenge.get();
            if (now.isBefore(challenge.getLastSentAt().plus(RESEND_COOLDOWN))
                    || challenge.getResendCount() >= MAX_RESENDS) {
                return;
            }
            String otp = generateOtp();
            challenge.resend(passwordEncoder.encode(otp), now.plus(OTP_LIFETIME), now);
            passwordResetChallengeRepository.save(challenge);
            sendResetOtp(email, otp);
            return;
        }

        currentChallenge.ifPresent(passwordResetChallengeRepository::delete);
        String otp = generateOtp();
        challenge = new PasswordResetChallenge(user, passwordEncoder.encode(otp), now.plus(OTP_LIFETIME), now);
        passwordResetChallengeRepository.save(challenge);
        sendResetOtp(email, otp);
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        String tokenHash = sha256(request.token());
        Optional<PasswordResetChallenge> candidate =
                passwordResetChallengeRepository.findByResetTokenHash(tokenHash);
        if (candidate.isEmpty()) {
            throw invalidResetToken();
        }
        userRepository.findByIdForUpdate(candidate.get().getUser().getId())
                .orElseThrow(this::invalidResetToken);
        PasswordResetChallenge challenge = passwordResetChallengeRepository
                .findByResetTokenHashForUpdate(tokenHash).orElseThrow(this::invalidResetToken);
        Instant now = clock.instant();
        if (challenge.getVerifiedAt() == null || challenge.getResetTokenExpiresAt() == null
                || !now.isBefore(challenge.getResetTokenExpiresAt())) {
            throw invalidResetToken();
        }

        User user = challenge.getUser();
        user.setPassword(passwordEncoder.encode(request.password()));
        userRepository.save(user);
        passwordResetChallengeRepository.delete(challenge);
        passwordResetTokenRepository.deleteByUser(user);
    }

    @Transactional
    public Optional<String> verifyPasswordResetOtp(VerifyPasswordResetOtpRequest request, String remoteAddress) {
        if (!passwordResetRateLimiter.tryAcquirePasswordReset(remoteAddress)) {
            throw new RateLimitExceededException();
        }

        String email = request.email().trim().toLowerCase(Locale.ROOT);
        Optional<User> matchingUser = userRepository.findByEmailIgnoreCaseForUpdate(email);
        if (matchingUser.isEmpty()) {
            return Optional.empty();
        }
        Optional<PasswordResetChallenge> currentChallenge =
                passwordResetChallengeRepository.findByUserIdForUpdate(matchingUser.get().getId());
        if (currentChallenge.isEmpty()) {
            return Optional.empty();
        }

        PasswordResetChallenge challenge = currentChallenge.get();
        Instant now = clock.instant();
        if (challenge.getVerifiedAt() != null) {
            return Optional.empty();
        }
        if (!now.isBefore(challenge.getOtpExpiresAt())
                || challenge.getAttemptCount() >= MAX_OTP_ATTEMPTS) {
            passwordResetChallengeRepository.delete(challenge);
            return Optional.empty();
        }
        if (!passwordEncoder.matches(request.otp(), challenge.getOtpHash())) {
            challenge.recordFailedAttempt();
            if (challenge.getAttemptCount() >= MAX_OTP_ATTEMPTS) {
                passwordResetChallengeRepository.delete(challenge);
            } else {
                passwordResetChallengeRepository.save(challenge);
            }
            return Optional.empty();
        }

        String resetToken = generateResetToken();
        challenge.verify(sha256(resetToken), now.plus(RESET_TOKEN_LIFETIME), now);
        passwordResetChallengeRepository.save(challenge);
        return Optional.of(resetToken);
    }

    private void sendResetOtp(String email, String otp) {
        try {
            passwordResetEmailService.sendOtp(email, otp);
        } catch (MailException deliveryFailure) {
            LOG.warn("Password reset email delivery failed");
            throw new IllegalStateException("Password reset email is temporarily unavailable; contact support.");
        }
    }

    private String generateOtp() {
        return String.format(Locale.ROOT, "%06d", secureRandom.nextInt(1_000_000));
    }

    private String generateResetToken() {
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

    private IllegalArgumentException invalidResetToken() {
        return new IllegalArgumentException("Invalid or expired password reset token");
    }
}
