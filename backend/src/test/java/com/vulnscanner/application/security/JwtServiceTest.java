package com.vulnscanner.application.security;

import com.vulnscanner.application.config.JwtProperties;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.user.User;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class JwtServiceTest {

    @Test
    void rejectsMissingAndWhitespaceOnlySecrets() {
        IllegalStateException missing = assertThrows(IllegalStateException.class,
                () -> service(null));
        IllegalStateException blank = assertThrows(IllegalStateException.class,
                () -> service(" \t "));

        assertEquals("JWT secret must be configured", missing.getMessage());
        assertEquals("JWT secret must be configured", blank.getMessage());
    }

    @Test
    void rejectsSecretsShorterThan256Bits() {
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> service("short-secret"));

        assertEquals("JWT secret must be at least 32 UTF-8 bytes for HS256", failure.getMessage());
    }

    @Test
    void acceptsASecretOfAtLeast256Bits() {
        assertDoesNotThrow(() -> service("0123456789abcdef0123456789abcdef"));
    }

    @Test
    void tokensRemainValidAcrossServiceRestartsWithTheSameSecret() {
        String secret = "0123456789abcdef0123456789abcdef";
        JwtService initialService = service(secret);
        JwtService restartedService = service(secret);

        String token = initialService.generateToken(user());

        assertTrue(restartedService.isTokenValid(token));
    }

    @Test
    void rejectsInvalidAndExpiredTokens() {
        JwtService service = service("0123456789abcdef0123456789abcdef");
        JwtService otherKeyService = service("abcdef0123456789abcdef0123456789");
        JwtProperties expiredProperties = new JwtProperties();
        expiredProperties.setSecret("0123456789abcdef0123456789abcdef");
        expiredProperties.setExpirationMs(-1);
        JwtService expiredTokenService = new JwtService(
                expiredProperties, mock(TokenBlacklistRepository.class));
        expiredTokenService.init();

        assertFalse(service.isTokenValid("not-a-jwt"));
        assertFalse(otherKeyService.isTokenValid(service.generateToken(user())));
        assertFalse(expiredTokenService.isTokenValid(expiredTokenService.generateToken(user())));
    }

    private JwtService service(String secret) {
        JwtProperties properties = new JwtProperties();
        properties.setSecret(secret);
        JwtService service = new JwtService(properties, mock(TokenBlacklistRepository.class));
        service.init();
        return service;
    }

    private User user() {
        User user = new User();
        user.setEmail("user@example.invalid");
        user.setRoles(Set.of(new Role(RoleName.SECURITY_ANALYST)));
        return user;
    }
}
