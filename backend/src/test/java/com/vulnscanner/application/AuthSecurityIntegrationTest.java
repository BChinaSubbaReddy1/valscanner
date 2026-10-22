package com.vulnscanner.application;

import com.vulnscanner.application.organization.*;
import com.vulnscanner.application.role.*;
import com.vulnscanner.application.user.*;
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
