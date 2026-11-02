package com.vulnscanner.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.auth.PasswordResetEmailService;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.mockito.ArgumentCaptor;

final class LoginOtpTestSupport {
    private static final AtomicInteger ADDRESS_SEQUENCE = new AtomicInteger(1);

    private LoginOtpTestSupport() {
    }

    static String completeLogin(MockMvc mockMvc, ObjectMapper objectMapper,
                                PasswordResetEmailService emailService,
                                String email, String password) throws Exception {
        clearInvocations(emailService);
        String startBody = mockMvc.perform(post("/api/auth/login")
                        .with(remoteAddress(nextAddress()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"%s"}
                                """.formatted(email, password)))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        JsonNode challengeResponse = objectMapper.readTree(startBody).path("data");
        String challengeToken = challengeResponse.path("challengeToken").asText();
        if (challengeToken.isBlank() || challengeResponse.has("token")) {
            throw new AssertionError("Password authentication must return only a login OTP challenge");
        }

        ArgumentCaptor<String> otpCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailService).sendLoginOtp(eq(email), otpCaptor.capture(), any(Duration.class));
        String verifyBody = mockMvc.perform(post("/api/auth/verify-login-otp")
                        .with(remoteAddress(nextAddress()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"challengeToken":"%s","otp":"%s"}
                                """.formatted(challengeToken, otpCaptor.getValue())))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(verifyBody).path("data").path("token").asText();
    }

    static int loginStatus(MockMvc mockMvc, String email, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                        .with(remoteAddress(nextAddress()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"%s"}
                                """.formatted(email, password)))
                .andReturn().getResponse().getStatus();
    }

    static RequestPostProcessor remoteAddress(String address) {
        return request -> {
            request.setRemoteAddr(address);
            return request;
        };
    }

    private static String nextAddress() {
        int sequence = ADDRESS_SEQUENCE.getAndIncrement();
        return "198.18." + ((sequence / 250) % 250) + "." + ((sequence % 250) + 1);
    }
}
