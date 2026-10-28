package com.vulnscanner.application;

import com.vulnscanner.application.organization.*;
import com.vulnscanner.application.role.*;
import com.vulnscanner.application.user.*;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.RequestDispatcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AuthSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private OrganizationRepository organizationRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        organizationRepository.deleteAll();

        for (RoleName roleName : new RoleName[]{
                RoleName.SUPER_ADMIN, RoleName.ADMIN, RoleName.SECURITY_ANALYST}) {
            if (roleRepository.findByName(roleName).isEmpty()) {
                roleRepository.save(new Role(roleName));
            }
        }
    }

    @Test
    void unauthenticatedRequestsAreRejected() throws Exception {
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tamperedJwtSignatureIsRejectedByProtectedEndpoint() throws Exception {
        User admin = createUser(RoleName.SUPER_ADMIN, "tampered-token-super@example.com");
        String token = authenticate(admin.getEmail(), "Password123!");
        String[] tokenParts = token.split("\\.");
        String signature = tokenParts[2];
        String replacement = signature.charAt(0) == 'A' ? "B" : "A";
        String tamperedToken = tokenParts[0] + "." + tokenParts[1] + "."
                + replacement + signature.substring(1);

        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + tamperedToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void revokedJwtIsRejectedByProtectedEndpoint() throws Exception {
        User admin = createUser(RoleName.SUPER_ADMIN, "revoked-token-super@example.com");
        String token = authenticate(admin.getEmail(), "Password123!");

        mockMvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void suspendedAccountCannotUsePreviouslyIssuedJwt() throws Exception {
        User admin = createUser(RoleName.SUPER_ADMIN, "suspended-token-super@example.com");
        String token = authenticate(admin.getEmail(), "Password123!");
        admin.setStatus(UserStatus.SUSPENDED);
        userRepository.saveAndFlush(admin);

        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registrationIsPublicAndIgnoresStaleBearerTokensWithoutOpeningProtectedRoutes() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/auth/register")
                        .header("Authorization", "Bearer stale-invalid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/auth/register")
                        .header("Authorization", "Bearer stale-invalid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Public","lastName":"Applicant",
                                 "email":"public-applicant@example.com","password":"SecurePassword123!",
                                 "role":"ADMIN","organizationName":"Public Applicant Organization"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.email").value("public-applicant@example.com"));

        mockMvc.perform(get("/api/auth/register"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/users/me")
                        .header("Authorization", "Bearer stale-invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void anonymousErrorDispatchReturnsOriginalValidationStatusInsteadOfUnauthorized() throws Exception {
        mockMvc.perform(get("/error").with(request -> {
                    request.setDispatcherType(DispatcherType.ERROR);
                    request.setAttribute(RequestDispatcher.ERROR_STATUS_CODE, 400);
                    request.setAttribute(RequestDispatcher.ERROR_REQUEST_URI, "/api/auth/register");
                    return request;
                }))
                .andExpect(status().isBadRequest());
    }

    @Test
    void passwordResetEndpointReportsUnavailableWhenDeliveryIsNotConfigured() throws Exception {
        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"user@example.com\"}"))
                .andExpect(status().isServiceUnavailable());
    }

    @Test
    void legacyCustomerRoleIsNotProvisionedForNewInstall() {
        org.junit.jupiter.api.Assertions.assertTrue(roleRepository.findByName(RoleName.CUSTOMER).isEmpty());
    }

    @Test
    void superAdminCanReadOrganizationRegistrationMetadataWithoutTenantMembership() throws Exception {
        User admin = createUser(RoleName.SUPER_ADMIN, "super@example.com");
        Organization org = createOrganization(admin, "Acme");

        String token = authenticate(admin.getEmail(), "Password123!");
        mockMvc.perform(get("/api/organizations/{id}", org.getId()).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    private String authenticate(String email, String password) throws Exception {
        String json = "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return response.split("\"token\":\"")[1].split("\"")[0];
    }

    private User createUser(RoleName roleName, String email) {
        User user = new User();
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode("Password123!"));
        user.setStatus(UserStatus.ACTIVE);
        Role role = roleRepository.findByName(roleName).orElseThrow();
        user.setRoles(java.util.Set.of(role));
        return userRepository.save(user);
    }

    private Organization createOrganization(User user, String name) {
        Organization org = new Organization();
        org.setName(name);
        org.setContactEmail("ops@example.com");
        org.setPrimaryContactName("Ops");
        org.setStatus(OrganizationStatus.PENDING);
        return organizationRepository.save(org);
    }
}
