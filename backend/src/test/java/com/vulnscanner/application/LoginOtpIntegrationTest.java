package com.vulnscanner.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.auth.AuthService;
import com.vulnscanner.application.auth.LoginOtpChallengeResponse;
import com.vulnscanner.application.auth.PasswordResetEmailService;
import com.vulnscanner.application.auth.PasswordResetRateLimiter;
import com.vulnscanner.application.user.LoginOtpChallenge;
import com.vulnscanner.application.user.LoginOtpChallengeRepository;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.MailSendException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.UUID;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class LoginOtpIntegrationTest {
    private static final Pattern OTP_PATTERN = Pattern.compile("\\b(\\d{6})\\b");
    private static final AtomicInteger ADDRESS_SEQUENCE = new AtomicInteger(1);

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private LoginOtpChallengeRepository challengeRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private AuthService authService;
    @Autowired private PasswordResetRateLimiter rateLimiter;
    @MockBean private PasswordResetEmailService emailService;
    @Value("${app.auth.login-otp.max-sends-per-window}")
    private int maxSendsPerWindow;

    private User user;

    @BeforeEach
    void setUp() {
        reset(emailService);
        when(emailService.isConfigured()).thenReturn(true);
        Role role = roleRepository.findByName(RoleName.SUPER_ADMIN).orElseThrow();
        user = createUser("login-" + UUID.randomUUID() + "@example.test", role, UserStatus.ACTIVE);
    }

    @Test
    void validPasswordCreatesChallengeWithoutJwtAndValidOtpIssuesJwtOnlyOnce() throws Exception {
        String startBody = startLogin(user, "CorrectPassword123!");
        JsonNode challengeData = objectMapper.readTree(startBody).path("data");
        String challengeToken = challengeData.path("challengeToken").asText();
        assertFalse(challengeData.has("token"));
        assertEquals("l***@example.test", challengeData.path("maskedEmail").asText());

        LoginOtpChallenge persisted = challengeRepository.findByUserIdForUpdate(user.getId()).orElseThrow();
        String otp = sentLoginOtp();
        assertNotEquals(otp, persisted.getOtpHash());
        assertTrue(passwordEncoder.matches(otp, persisted.getOtpHash()));
        assertTrue(persisted.getExpiresAt().isAfter(Instant.now()));
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized());

        String verifyBody = verifyLogin(challengeToken, otp)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.token").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        assertTrue(objectMapper.readTree(verifyBody).path("data").path("roles").isArray());
        verifyLogin(challengeToken, otp).andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/users/me")
                        .header("Authorization", "Bearer "
                                + objectMapper.readTree(verifyBody).path("data").path("token").asText()))
                .andExpect(status().isOk());
    }

    @Test
    void fiveBrowserLoginFlowsCanShareAnIpAcrossGenerationAndVerification() throws Exception {
        String sharedAddress = "127.0.0.1";
        for (int browser = 0; browser < 5; browser++) {
            User browserUser = createUser("browser-" + UUID.randomUUID() + "@example.test",
                    roleRepository.findByName(RoleName.SUPER_ADMIN).orElseThrow(), UserStatus.ACTIVE);
            clearInvocations(emailService);
            String startBody = mockMvc.perform(post("/api/auth/login")
                            .with(LoginOtpTestSupport.remoteAddress(sharedAddress))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"email":"%s","password":"CorrectPassword123!"}
                                    """.formatted(browserUser.getEmail())))
                    .andExpect(status().isAccepted())
                    .andReturn().getResponse().getContentAsString();
            String token = challengeToken(startBody);
            verifyLogin(token, sentLoginOtp(), sharedAddress).andExpect(status().isOk());
        }
    }

    @Test
    void rateLimitsReturn429AndRemainIndependentByOperation() throws Exception {
        String sharedAddress = "127.0.0.2";
        for (int request = 0; request < 20; request++) {
            assertTrue(rateLimiter.tryAcquireLoginOtp(sharedAddress));
        }
        mockMvc.perform(post("/api/auth/login")
                        .with(LoginOtpTestSupport.remoteAddress(sharedAddress))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"CorrectPassword123!"}
                                """.formatted(user.getEmail())))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.message").value("Too many requests. Please try again later."));

        assertTrue(rateLimiter.tryAcquirePasswordReset(sharedAddress));
        assertTrue(rateLimiter.tryAcquireLoginOtpVerification("unrelated-challenge"));
        assertTrue(rateLimiter.tryAcquireLoginOtpResend("unrelated-challenge"));

        String verifyToken = challengeToken(startLogin(user, "CorrectPassword123!"));
        String verifyTokenHash = sha256(verifyToken);
        for (int request = 0; request < 10; request++) {
            assertTrue(rateLimiter.tryAcquireLoginOtpVerification(verifyTokenHash));
        }
        verifyLogin(verifyToken, "999999")
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.message").value("Too many requests. Please try again later."));
        assertEquals(0, challengeRepository.findByUserIdForUpdate(user.getId())
                .orElseThrow().getAttemptCount());

        String resendToken = challengeToken(startLogin(
                createUser("resend-" + UUID.randomUUID() + "@example.test",
                        roleRepository.findByName(RoleName.SUPER_ADMIN).orElseThrow(), UserStatus.ACTIVE),
                "CorrectPassword123!"));
        for (int request = 0; request < 5; request++) {
            assertTrue(rateLimiter.tryAcquireLoginOtpResend(sha256(resendToken)));
        }
        mockMvc.perform(post("/api/auth/resend-login-otp")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"challengeToken":"%s"}
                                """.formatted(resendToken)))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.message").value("Too many requests. Please try again later."));

        String resetAddress = "127.0.0.3";
        for (int request = 0; request < 5; request++) {
            assertTrue(rateLimiter.tryAcquirePasswordReset(resetAddress));
        }
        mockMvc.perform(post("/api/auth/forgot-password")
                        .with(LoginOtpTestSupport.remoteAddress(resetAddress))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s"}
                                """.formatted(user.getEmail())))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.message").value("Too many requests. Please try again later."));
    }

    @Test
    void invalidCredentialsAndIneligibleAccountsNeverReceiveLoginOtp() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"login-id","password":"CorrectPassword123!"}
                                """))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/auth/login")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"IncorrectPassword123!"}
                                """.formatted(user.getEmail())))
                .andExpect(status().isUnauthorized());
        verify(emailService, never()).sendLoginOtp(anyString(), anyString(), any(Duration.class));
        assertTrue(challengeRepository.findAll().isEmpty());

        user.setStatus(UserStatus.PENDING_APPROVAL);
        userRepository.saveAndFlush(user);
        mockMvc.perform(post("/api/auth/login")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"CorrectPassword123!"}
                                """.formatted(user.getEmail())))
                .andExpect(status().isUnauthorized());
        verify(emailService, never()).sendLoginOtp(anyString(), anyString(), any(Duration.class));
    }

    @Test
    void invalidOtpExpiresAndMaximumAttemptsExhaustTheChallenge() throws Exception {
        String token = challengeToken(startLogin(user, "CorrectPassword123!"));
        for (int attempt = 0; attempt < 4; attempt++) {
            verifyLogin(token, "999999").andExpect(status().isBadRequest());
        }
        LoginOtpChallenge challenge = challengeRepository.findByUserIdForUpdate(user.getId()).orElseThrow();
        assertEquals(4, challenge.getAttemptCount());
        verifyLogin(token, sentLoginOtp()).andExpect(status().isOk());
    }

    @Test
    void fifthIncorrectAttemptExhaustsOtpAndExpiredOtpIsRejected() throws Exception {
        String token = challengeToken(startLogin(user, "CorrectPassword123!"));
        for (int attempt = 0; attempt < 5; attempt++) {
            verifyLogin(token, "999999").andExpect(status().isBadRequest());
        }
        assertEquals(5, challengeRepository.findByUserIdForUpdate(user.getId()).orElseThrow().getAttemptCount());

        User expiredUser = createUser("expired-" + UUID.randomUUID() + "@example.test",
                roleRepository.findByName(RoleName.SUPER_ADMIN).orElseThrow(), UserStatus.ACTIVE);
        String expiredToken = challengeToken(startLogin(expiredUser, "CorrectPassword123!"));
        LoginOtpChallenge expiredChallenge =
                challengeRepository.findByUserIdForUpdate(expiredUser.getId()).orElseThrow();
        ReflectionTestUtils.setField(expiredChallenge, "expiresAt", Instant.now().minusSeconds(1));
        challengeRepository.saveAndFlush(expiredChallenge);
        verifyLogin(expiredToken, sentLoginOtp()).andExpect(status().isBadRequest());
    }

    @Test
    void resendRotatesChallengeAndEnforcesCooldownAndResendLimit() throws Exception {
        String firstToken = challengeToken(startLogin(user, "CorrectPassword123!"));
        mockMvc.perform(post("/api/auth/resend-login-otp")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"challengeToken":"%s"}
                                """.formatted(firstToken)))
                .andExpect(status().isBadRequest());

        LoginOtpChallenge challenge = challengeRepository.findByUserIdForUpdate(user.getId()).orElseThrow();
        ReflectionTestUtils.setField(challenge, "lastSentAt", Instant.now().minusSeconds(61));
        challengeRepository.saveAndFlush(challenge);
        String resendBody = mockMvc.perform(post("/api/auth/resend-login-otp")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"challengeToken":"%s"}
                                """.formatted(firstToken)))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        String nextToken = challengeToken(resendBody);
        assertNotEquals(firstToken, nextToken);
        verifyLogin(firstToken, sentLoginOtp()).andExpect(status().isBadRequest());
        verifyLogin(nextToken, sentLoginOtp()).andExpect(status().isOk());

        User limitedUser = createUser("limited-" + UUID.randomUUID() + "@example.test",
                roleRepository.findByName(RoleName.SUPER_ADMIN).orElseThrow(), UserStatus.ACTIVE);
        String limitedToken = challengeToken(startLogin(limitedUser, "CorrectPassword123!"));
        LoginOtpChallenge limitedChallenge =
                challengeRepository.findByUserIdForUpdate(limitedUser.getId()).orElseThrow();
        ReflectionTestUtils.setField(limitedChallenge, "resendCount", 3);
        ReflectionTestUtils.setField(limitedChallenge, "lastSentAt", Instant.now().minusSeconds(61));
        challengeRepository.saveAndFlush(limitedChallenge);
        mockMvc.perform(post("/api/auth/resend-login-otp")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"challengeToken":"%s"}
                                """.formatted(limitedToken)))
                .andExpect(status().isBadRequest());

        ReflectionTestUtils.setField(limitedChallenge, "sendCount", maxSendsPerWindow);
        challengeRepository.saveAndFlush(limitedChallenge);
        mockMvc.perform(post("/api/auth/login")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"CorrectPassword123!"}
                                """.formatted(limitedUser.getEmail())))
                .andExpect(status().isConflict());
    }

    @Test
    void emailDeliveryFailureDoesNotCreateChallengeOrAuthenticate() throws Exception {
        doThrow(new MailSendException("test-only provider details"))
                .when(emailService).sendLoginOtp(anyString(), anyString(), any(Duration.class));
        mockMvc.perform(post("/api/auth/login")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"CorrectPassword123!"}
                                """.formatted(user.getEmail())))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value(
                        "Login verification email is temporarily unavailable; contact support."));
        assertTrue(challengeRepository.findAll().isEmpty());
    }

    @Test
    void passwordResetOtpCannotAuthenticateAndLoginOtpIsNotAResetCapability() throws Exception {
        authService.requestPasswordReset(
                new com.vulnscanner.application.auth.ForgotPasswordRequest(user.getEmail()), "198.18.100.1");
        org.mockito.ArgumentCaptor<String> resetOtpCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(emailService).sendOtp(eq(user.getEmail()), resetOtpCaptor.capture());
        String resetOtp = resetOtpCaptor.getValue();

        String loginChallengeToken = challengeToken(startLogin(user, "CorrectPassword123!"));
        verifyLogin(loginChallengeToken, resetOtp).andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","password":"NewPassword123!"}
                                """.formatted(loginChallengeToken)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginChallengesCannotBeUsedAcrossUsers() throws Exception {
        User secondUser = createUser("second-" + UUID.randomUUID() + "@example.test",
                roleRepository.findByName(RoleName.SUPER_ADMIN).orElseThrow(), UserStatus.ACTIVE);
        String firstToken = challengeToken(startLogin(user, "CorrectPassword123!"));
        String firstOtp = sentLoginOtp();
        String secondToken = challengeToken(startLogin(secondUser, "CorrectPassword123!"));
        String secondOtp = sentLoginOtp();

        verifyLogin(firstToken, secondOtp).andExpect(status().isBadRequest());
        verifyLogin(secondToken, firstOtp).andExpect(status().isBadRequest());
    }

    private User createUser(String email, Role role, UserStatus status) {
        User created = new User();
        created.setFirstName("Login");
        created.setLastName("Test");
        created.setEmail(email);
        created.setPassword(passwordEncoder.encode("CorrectPassword123!"));
        created.setStatus(status);
        created.setRoles(Set.of(role));
        return userRepository.saveAndFlush(created);
    }

    private String startLogin(User target, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .with(remoteAddress())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"%s"}
                                """.formatted(target.getEmail(), password)))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
    }

    private org.springframework.test.web.servlet.ResultActions verifyLogin(String token, String otp)
            throws Exception {
        return verifyLogin(token, otp, null);
    }

    private org.springframework.test.web.servlet.ResultActions verifyLogin(String token, String otp, String address)
            throws Exception {
        return mockMvc.perform(post("/api/auth/verify-login-otp")
                .with(address == null ? remoteAddress() : LoginOtpTestSupport.remoteAddress(address))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"challengeToken":"%s","otp":"%s"}
                        """.formatted(token, otp)));
    }

    private String sha256(String value) throws NoSuchAlgorithmException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private String sentLoginOtp() {
        org.mockito.ArgumentCaptor<String> otpCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(emailService, atLeastOnce()).sendLoginOtp(anyString(), otpCaptor.capture(), any(Duration.class));
        return otpCaptor.getValue();
    }

    private String challengeToken(String response) throws Exception {
        return objectMapper.readTree(response).path("data").path("challengeToken").asText();
    }

    private RequestPostProcessor remoteAddress() {
        int sequence = ADDRESS_SEQUENCE.getAndIncrement();
        return LoginOtpTestSupport.remoteAddress(
                "198.19." + ((sequence / 250) % 250) + "." + ((sequence % 250) + 1));
    }
}
