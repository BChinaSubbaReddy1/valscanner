package com.vulnscanner.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.auth.PasswordResetEmailService;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.user.PasswordResetChallenge;
import com.vulnscanner.application.user.PasswordResetChallengeRepository;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "app.email.enabled=true",
        "MAIL_FROM=reset@example.test",
        "spring.mail.host=localhost",
        "spring.mail.port=2525",
        "spring.mail.username=otp-test-user",
        "spring.mail.password=otp-test-password",
        "spring.mail.properties.mail.smtp.auth=true",
        "spring.mail.properties.mail.smtp.starttls.enable=true",
        "spring.mail.properties.mail.smtp.ssl.enable=false",
        "management.health.mail.enabled=false"
})
@Transactional
class PasswordResetIntegrationTest {
    private static final Pattern OTP_PATTERN = Pattern.compile("\\b(\\d{6})\\b");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordResetChallengeRepository challengeRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MailProperties mailProperties;

    @Autowired
    private PasswordResetEmailService passwordResetEmailService;

    @MockBean
    private JavaMailSender mailSender;

    private User user;

    @Test
    void mapsConfiguredMailPropertiesAndRequiresCompleteSettings() {
        assertEquals("localhost", mailProperties.getHost());
        assertEquals(2525, mailProperties.getPort());
        assertEquals("otp-test-user", mailProperties.getUsername());
        assertEquals("otp-test-password", mailProperties.getPassword());
        assertEquals("true", mailProperties.getProperties().get("mail.smtp.auth"));
        assertEquals("true", mailProperties.getProperties().get("mail.smtp.starttls.enable"));
        assertEquals("false", mailProperties.getProperties().get("mail.smtp.ssl.enable"));
        assertTrue(passwordResetEmailService.isConfigured());
    }

    @BeforeEach
    void setUp() {
        reset(mailSender);
        Role role = roleRepository.findByName(RoleName.SUPER_ADMIN).orElseThrow();
        user = new User();
        user.setFirstName("Reset");
        user.setLastName("Test");
        user.setEmail("reset-" + UUID.randomUUID() + "@example.com");
        user.setPassword(passwordEncoder.encode("OriginalPassword123!"));
        user.setStatus(UserStatus.ACTIVE);
        user.setRoles(java.util.Set.of(role));
        user = userRepository.saveAndFlush(user);
    }

    @Test
    void verifiesHashedOtpResetsPasswordOnceAndAllowsLoginWithNewPassword() throws Exception {
        String requestResponse = requestOtp(user.getEmail(), "192.0.2.10")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(
                        "If an account matches that email, a verification code will be sent."))
                .andReturn().getResponse().getContentAsString();
        String otp = deliveredOtp();
        ArgumentCaptor<SimpleMailMessage> sentMessage = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(sentMessage.capture());
        assertEquals("reset@example.test", sentMessage.getValue().getFrom());
        assertArrayEquals(new String[]{user.getEmail()}, sentMessage.getValue().getTo());
        assertFalse(requestResponse.contains(otp));

        PasswordResetChallenge challenge = challengeRepository.findByUserIdForUpdate(user.getId()).orElseThrow();
        assertNotEquals(otp, challenge.getOtpHash());
        assertTrue(passwordEncoder.matches(otp, challenge.getOtpHash()));
        assertTrue(challenge.getOtpExpiresAt().isAfter(Instant.now()));

        String verificationResponse = mockMvc.perform(post("/api/auth/verify-reset-otp")
                        .with(remoteAddress("192.0.2.11"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","otp":"%s"}
                                """.formatted(user.getEmail(), otp)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.resetToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        JsonNode verification = objectMapper.readTree(verificationResponse);
        String resetToken = verification.path("data").path("resetToken").asText();

        mockMvc.perform(post("/api/auth/verify-reset-otp")
                        .with(remoteAddress("192.0.2.12"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","otp":"%s"}
                                """.formatted(user.getEmail(), otp)))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/auth/reset-password")
                        .with(remoteAddress("192.0.2.13"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","password":"ReplacementPassword123!"}
                                """.formatted(resetToken)))
                .andExpect(status().isOk());

        assertTrue(passwordEncoder.matches("ReplacementPassword123!",
                userRepository.findById(user.getId()).orElseThrow().getPassword()));
        assertTrue(challengeRepository.findByUserIdForUpdate(user.getId()).isEmpty());

        mockMvc.perform(post("/api/auth/reset-password")
                        .with(remoteAddress("192.0.2.14"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","password":"AnotherPassword123!"}
                                """.formatted(resetToken)))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"OriginalPassword123!"}
                                """.formatted(user.getEmail())))
                .andExpect(status().isUnauthorized());
        String loginChallengeBody = mockMvc.perform(post("/api/auth/login")
                        .with(remoteAddress("192.0.2.50"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"ReplacementPassword123!"}
                                """.formatted(user.getEmail())))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.data.token").doesNotExist())
                .andReturn().getResponse().getContentAsString();
        String loginChallengeToken = objectMapper.readTree(loginChallengeBody)
                .path("data").path("challengeToken").asText();
        String loginOtp = deliveredOtp();
        mockMvc.perform(post("/api/auth/verify-login-otp")
                        .with(remoteAddress("192.0.2.51"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"challengeToken":"%s","otp":"%s"}
                                """.formatted(loginChallengeToken, loginOtp)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.token").isNotEmpty());
        assertNotNull(requestResponse);
    }

    @Test
    void resetEndpointRejectsSevenCharactersAndAcceptsEightAndLongerPasswords() throws Exception {
        String eightCharacterToken = issueResetToken("192.0.2.40", "192.0.2.41");

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","password":"Pass123"}
                                """.formatted(eightCharacterToken)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(
                        "Validation failed: Password must be at least 8 characters long."));

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","password":"Pass1234"}
                                """.formatted(eightCharacterToken)))
                .andExpect(status().isOk());

        String longerPasswordToken = issueResetToken("192.0.2.42", "192.0.2.43");
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","password":"Password123!"}
                                """.formatted(longerPasswordToken)))
                .andExpect(status().isOk());
    }

    @Test
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    void reportsEmailDeliveryFailureWithoutLeakingProviderDetailsOrKeepingChallenge() throws Exception {
        String providerFailure = "test-only SMTP provider diagnostic";
        doThrow(new MailSendException(providerFailure)).when(mailSender).send(any(SimpleMailMessage.class));

        try {
            String response = requestOtp(user.getEmail(), "192.0.2.15")
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.message").value(
                            "Password reset email is temporarily unavailable; contact support."))
                    .andReturn().getResponse().getContentAsString();

            assertFalse(response.contains(providerFailure));
            assertTrue(challengeRepository.findAll().stream()
                    .noneMatch(challenge -> challenge.getUser().getId().equals(user.getId())));
        } finally {
            userRepository.delete(user);
        }
    }

    @Test
    void rejectsExpiredOtpAndConsumesFiveIncorrectAttempts() throws Exception {
        requestOtp(user.getEmail(), "192.0.2.20").andExpect(status().isOk());
        String otp = deliveredOtp();
        PasswordResetChallenge challenge = challengeRepository.findByUserIdForUpdate(user.getId()).orElseThrow();
        ReflectionTestUtils.setField(challenge, "otpExpiresAt", Instant.now().minusSeconds(1));
        challengeRepository.saveAndFlush(challenge);

        mockMvc.perform(post("/api/auth/verify-reset-otp")
                        .with(remoteAddress("192.0.2.21"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","otp":"%s"}
                                """.formatted(user.getEmail(), otp)))
                .andExpect(status().isBadRequest());
        assertTrue(challengeRepository.findByUserIdForUpdate(user.getId()).isEmpty());

        requestOtp(user.getEmail(), "192.0.2.22").andExpect(status().isOk());
        otp = deliveredOtp();
        String incorrectOtp = otp.equals("000000") ? "000001" : "000000";
        for (int attempt = 0; attempt < 5; attempt++) {
            mockMvc.perform(post("/api/auth/verify-reset-otp")
                            .with(remoteAddress("198.51.100." + (attempt + 1)))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"email":"%s","otp":"%s"}
                                    """.formatted(user.getEmail(), incorrectOtp)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.message").value("Invalid or expired verification code"));
        }
        assertTrue(challengeRepository.findByUserIdForUpdate(user.getId()).isEmpty());
        mockMvc.perform(post("/api/auth/verify-reset-otp")
                        .with(remoteAddress("198.51.100.20"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","otp":"%s"}
                                """.formatted(user.getEmail(), otp)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsEmailOnlyPasswordChangesAndExpiredResetCapabilities() throws Exception {
        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"ReplacementPassword123!"}
                                """.formatted(user.getEmail())))
                .andExpect(status().isBadRequest());
        assertTrue(passwordEncoder.matches("OriginalPassword123!",
                userRepository.findById(user.getId()).orElseThrow().getPassword()));

        requestOtp(user.getEmail(), "192.0.2.40").andExpect(status().isOk());
        String otp = deliveredOtp();
        String verificationResponse = mockMvc.perform(post("/api/auth/verify-reset-otp")
                        .with(remoteAddress("192.0.2.41"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","otp":"%s"}
                                """.formatted(user.getEmail(), otp)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String resetToken = objectMapper.readTree(verificationResponse)
                .path("data").path("resetToken").asText();

        PasswordResetChallenge challenge = challengeRepository.findByUserIdForUpdate(user.getId()).orElseThrow();
        ReflectionTestUtils.setField(challenge, "resetTokenExpiresAt", Instant.now().minusSeconds(1));
        challengeRepository.saveAndFlush(challenge);

        mockMvc.perform(post("/api/auth/reset-password")
                        .with(remoteAddress("192.0.2.42"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","password":"ReplacementPassword123!"}
                                """.formatted(resetToken)))
                .andExpect(status().isBadRequest());
        assertTrue(passwordEncoder.matches("OriginalPassword123!",
                userRepository.findById(user.getId()).orElseThrow().getPassword()));
    }

    @Test
    void appliesResendCooldownAndPerChallengeResendLimit() throws Exception {
        requestOtp(user.getEmail(), "203.0.113.1").andExpect(status().isOk());
        String firstOtp = deliveredOtp();

        requestOtp(user.getEmail(), "203.0.113.2").andExpect(status().isOk());
        verify(mailSender, times(1)).send(any(SimpleMailMessage.class));

        for (int resend = 0; resend < 3; resend++) {
            PasswordResetChallenge challenge =
                    challengeRepository.findByUserIdForUpdate(user.getId()).orElseThrow();
            ReflectionTestUtils.setField(challenge, "lastSentAt", Instant.now().minusSeconds(61));
            challengeRepository.saveAndFlush(challenge);
            requestOtp(user.getEmail(), "203.0.113." + (resend + 3)).andExpect(status().isOk());
        }

        PasswordResetChallenge challenge = challengeRepository.findByUserIdForUpdate(user.getId()).orElseThrow();
        assertEquals(3, challenge.getResendCount());
        assertNotEquals(firstOtp, deliveredOtp());

        ReflectionTestUtils.setField(challenge, "lastSentAt", Instant.now().minusSeconds(61));
        challengeRepository.saveAndFlush(challenge);
        requestOtp(user.getEmail(), "203.0.113.10").andExpect(status().isOk());
        verify(mailSender, times(4)).send(any(SimpleMailMessage.class));
    }

    @Test
    void registeredAndUnregisteredForgotPasswordRequestsShareTheSameResponse() throws Exception {
        String registered = requestOtp(user.getEmail(), "192.0.2.30")
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String unregistered = requestOtp("missing-" + UUID.randomUUID() + "@example.com", "192.0.2.31")
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        JsonNode registeredPayload = objectMapper.readTree(registered);
        JsonNode unregisteredPayload = objectMapper.readTree(unregistered);
        assertEquals(registeredPayload.path("message"), unregisteredPayload.path("message"));
        assertEquals(registeredPayload.path("data"), unregisteredPayload.path("data"));
        verify(mailSender, times(1)).send(any(SimpleMailMessage.class));
    }

    private org.springframework.test.web.servlet.ResultActions requestOtp(String email, String ip) throws Exception {
        return mockMvc.perform(post("/api/auth/forgot-password")
                .with(remoteAddress(ip))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s"}
                        """.formatted(email)));
    }

    private String issueResetToken(String requestIp, String verifyIp) throws Exception {
        requestOtp(user.getEmail(), requestIp).andExpect(status().isOk());
        String otp = deliveredOtp();
        String response = mockMvc.perform(post("/api/auth/verify-reset-otp")
                                .with(remoteAddress(verifyIp))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {"email":"%s","otp":"%s"}
                                        """.formatted(user.getEmail(), otp)))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(response).path("data").path("resetToken").asText();
    }

    private String deliveredOtp() {
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, atLeastOnce()).send(messageCaptor.capture());
        String text = messageCaptor.getValue().getText();
        Matcher matcher = OTP_PATTERN.matcher(text);
        assertTrue(matcher.find(), "The email should contain a six-digit OTP");
        return matcher.group(1);
    }

    private RequestPostProcessor remoteAddress(String address) {
        return request -> {
            request.setRemoteAddr(address);
            return request;
        };
    }
}
