package com.vulnscanner.application.auth;

import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.security.JwtService;
import com.vulnscanner.application.user.PasswordResetChallengeRepository;
import com.vulnscanner.application.user.PasswordResetTokenRepository;
import com.vulnscanner.application.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class AuthPasswordResetTest {

    @Test
    void resetRequestsFailSafelyAndDoNotLookUpAccountsWhenDeliveryIsDisabled() {
        UserRepository users = mock(UserRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        PasswordResetEmailService emailService = mock(PasswordResetEmailService.class);
        when(emailService.isConfigured()).thenReturn(false);
        AuthService service = service(users, encoder, emailService);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> service.requestPasswordReset(
                        new ForgotPasswordRequest("user@example.invalid"), "192.0.2.1"));

        assertEquals("Password reset email is temporarily unavailable; contact support.", failure.getMessage());
        verifyNoInteractions(users, encoder);
    }

    @Test
    void passwordResetRequiresAValidVerifiedResetCapability() {
        UserRepository users = mock(UserRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        PasswordResetChallengeRepository challenges = mock(PasswordResetChallengeRepository.class);
        when(challenges.findByResetTokenHash(anyString())).thenReturn(java.util.Optional.empty());
        AuthService service = service(users, encoder, mock(PasswordResetEmailService.class), challenges);

        assertThrows(IllegalArgumentException.class,
                () -> service.resetPassword(new ResetPasswordRequest("raw-token", "long-enough-password")));

        verify(users, never()).save(any());
        verify(encoder, never()).encode(anyString());
    }

    private AuthService service(UserRepository users, PasswordEncoder encoder,
                                PasswordResetEmailService emailService) {
        return service(users, encoder, emailService, mock(PasswordResetChallengeRepository.class));
    }

    private AuthService service(UserRepository users, PasswordEncoder encoder,
                                PasswordResetEmailService emailService,
                                PasswordResetChallengeRepository challenges) {
        return new AuthService(
                users,
                encoder,
                mock(RoleRepository.class),
                mock(OrganizationRepository.class),
                mock(AuditEventRepository.class),
                mock(JwtService.class),
                challenges,
                mock(PasswordResetTokenRepository.class),
                emailService,
                new PasswordResetRateLimiter(),
                java.time.Clock.systemUTC());
    }
}
