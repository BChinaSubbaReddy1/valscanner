package com.vulnscanner.application.role;

import com.vulnscanner.application.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class RoleInitializerTest {

    @Test
    void blankBootstrapConfigurationNeverCreatesAnAccount() {
        RoleRepository roles = mock(RoleRepository.class);
        UserRepository users = mock(UserRepository.class);
        PasswordEncoder passwords = mock(PasswordEncoder.class);
        when(roles.findByName(any())).thenReturn(Optional.of(new Role(RoleName.ADMIN)));

        RoleInitializer initializer = new RoleInitializer(roles, users, passwords);
        ReflectionTestUtils.setField(initializer, "superAdminEmail", " ");
        ReflectionTestUtils.setField(initializer, "superAdminPassword", " ");

        initializer.run(mock(ApplicationArguments.class));

        verify(users, never()).save(any());
        verify(passwords, never()).encode(anyString());
    }

    @Test
    void missingBootstrapConfigurationNeverCreatesAnAccount() {
        RoleRepository roles = mock(RoleRepository.class);
        UserRepository users = mock(UserRepository.class);
        PasswordEncoder passwords = mock(PasswordEncoder.class);
        when(roles.findByName(any())).thenReturn(Optional.of(new Role(RoleName.ADMIN)));

        RoleInitializer initializer = new RoleInitializer(roles, users, passwords);
        ReflectionTestUtils.setField(initializer, "superAdminEmail", null);
        ReflectionTestUtils.setField(initializer, "superAdminPassword", null);

        initializer.run(mock(ApplicationArguments.class));

        verify(users, never()).save(any());
        verify(passwords, never()).encode(anyString());
    }

    @Test
    void configuredEmailWithoutPasswordFailsWithoutProvisioning() {
        RoleRepository roles = mock(RoleRepository.class);
        UserRepository users = mock(UserRepository.class);
        PasswordEncoder passwords = mock(PasswordEncoder.class);
        when(roles.findByName(any())).thenReturn(Optional.of(new Role(RoleName.ADMIN)));
        when(users.findByEmail("admin@example.invalid")).thenReturn(Optional.empty());

        RoleInitializer initializer = new RoleInitializer(roles, users, passwords);
        ReflectionTestUtils.setField(initializer, "superAdminEmail", "admin@example.invalid");
        ReflectionTestUtils.setField(initializer, "superAdminPassword", "");

        assertThrows(IllegalStateException.class,
                () -> initializer.run(mock(ApplicationArguments.class)));

        verify(users, never()).save(any());
        verify(passwords, never()).encode(anyString());
    }

    @Test
    void explicitlyConfiguredBootstrapAccountUsesEncodedPassword() {
        RoleRepository roles = mock(RoleRepository.class);
        UserRepository users = mock(UserRepository.class);
        PasswordEncoder passwords = mock(PasswordEncoder.class);
        when(roles.findByName(any())).thenAnswer(invocation ->
                Optional.of(new Role(invocation.getArgument(0))));
        when(users.findByEmail("admin@example.invalid")).thenReturn(Optional.empty());
        when(passwords.encode("independent-explicit-password")).thenReturn("encoded-value");

        RoleInitializer initializer = new RoleInitializer(roles, users, passwords);
        ReflectionTestUtils.setField(initializer, "superAdminEmail", "ADMIN@example.invalid ");
        ReflectionTestUtils.setField(initializer, "superAdminPassword", "independent-explicit-password");

        initializer.run(mock(ApplicationArguments.class));

        verify(users).save(argThat(user ->
                "admin@example.invalid".equals(user.getEmail())
                        && "encoded-value".equals(user.getPassword())
                        && user.getRoles().stream().anyMatch(role -> role.getName() == RoleName.SUPER_ADMIN)));
    }
}
