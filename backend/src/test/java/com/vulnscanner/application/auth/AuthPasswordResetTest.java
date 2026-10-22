package com.vulnscanner.application.auth;

import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.security.JwtService;
import com.vulnscanner.application.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class AuthPasswordResetTest {

    @Test
    void resetRequestsFailClearlyWhenNoDeliveryServiceExists() {
        UserRepository users = mock(UserRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        AuthService service = service(users, encoder);

        ResponseStatusException failure = assertThrows(ResponseStatusException.class,
                () -> service.requestPasswordReset(new ForgotPasswordRequest("user@example.invalid")));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, failure.getStatusCode());
        verifyNoInteractions(users, encoder);
    }

    @Test
    void resetTokensAreNotAcceptedOrPersistedWithoutDeliverySupport() {
        UserRepository users = mock(UserRepository.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        AuthService service = service(users, encoder);

        ResponseStatusException failure = assertThrows(ResponseStatusException.class,
                () -> service.resetPassword(new ResetPasswordRequest("raw-token", "long-enough-password")));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, failure.getStatusCode());
        verifyNoInteractions(users, encoder);
    }

    private AuthService service(UserRepository users, PasswordEncoder encoder) {
        return new AuthService(
                mock(AuthenticationManager.class),
                users,
                encoder,
                mock(RoleRepository.class),
                mock(OrganizationRepository.class),
                mock(AuditEventRepository.class),
                mock(JwtService.class));
    }
}
