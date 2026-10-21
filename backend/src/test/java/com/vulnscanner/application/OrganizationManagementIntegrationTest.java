package com.vulnscanner.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
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

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class OrganizationManagementIntegrationTest {
    private static final String PASSWORD = "SecurePassword123!";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private OrganizationRepository organizationRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private AuditEventRepository auditEventRepository;

    @BeforeEach
    void initializeRoles() {
        for (RoleName name : new RoleName[]{
                RoleName.SUPER_ADMIN, RoleName.ADMIN, RoleName.SECURITY_ANALYST}) {
            roleRepository.findByName(name).orElseGet(() -> roleRepository.save(new Role(name)));
        }
    }

    @Test
    void dashboardAndUserListAreOrganizationScopedAndDoNotExposeEmail() throws Exception {
        Organization organization = approvedOrganization("Tenant One");
        User admin = createUser("admin-one@example.com", RoleName.ADMIN, UserStatus.ACTIVE, organization);
        createUser("analyst-one@example.com", RoleName.SECURITY_ANALYST, UserStatus.ACTIVE, organization);
        User legacyCustomer = createUser("customer-one@example.com", RoleName.CUSTOMER,
                UserStatus.PENDING_APPROVAL, organization);
        createUser("analyst-suspended@example.com", RoleName.SECURITY_ANALYST, UserStatus.SUSPENDED, organization);
        Organization otherOrganization = approvedOrganization("Tenant Two");
        User otherMember = createUser("other@example.com", RoleName.SECURITY_ANALYST, UserStatus.ACTIVE, otherOrganization);
        String token = login(admin.getEmail());

        mockMvc.perform(get("/api/organizations/me/dashboard")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalUsers").value(4))
                .andExpect(jsonPath("$.data.approvedUsers").value(2))
                .andExpect(jsonPath("$.data.pendingApprovalRequests").value(0))
                .andExpect(jsonPath("$.data.suspendedUsers").value(1))
                .andExpect(jsonPath("$.data.activeSecurityAnalysts").value(1))
                .andExpect(jsonPath("$.data.customers").doesNotExist());

        mockMvc.perform(get("/api/organizations/me/users")
                        .param("search", "Test")
                        .param("role", "SECURITY_ANALYST")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content.length()").value(2))
                .andExpect(jsonPath("$.data.content[0].displayName").value("Test User"))
                .andExpect(jsonPath("$.data.content[0].email").doesNotExist())
                .andExpect(jsonPath("$.data.content[0].password").doesNotExist());

        mockMvc.perform(get("/api/organizations/me/users/{id}", otherMember.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/organizations/me/users")
                        .param("role", "CUSTOMER")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest());
        mockMvc.perform(get("/api/organizations/me/users/{id}", legacyCustomer.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/organizations/me/approval-requests/{id}/approve", legacyCustomer.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest());
        assertEquals(UserStatus.PENDING_APPROVAL, legacyCustomer.getStatus());
    }

    @Test
    void organizationAdminCanApproveSuspendRestoreAndDeactivateEligibleMembers() throws Exception {
        Organization organization = approvedOrganization("Member Actions");
        User admin = createUser("member-admin@example.com", RoleName.ADMIN, UserStatus.ACTIVE, organization);
        User pendingAnalyst = createUser("pending-analyst@example.com", RoleName.SECURITY_ANALYST,
                UserStatus.PENDING_APPROVAL, organization);
        User activeLegacyCustomer = createUser("active-customer@example.com", RoleName.CUSTOMER,
                UserStatus.ACTIVE, organization);
        User analyst = createUser("active-analyst@example.com", RoleName.SECURITY_ANALYST,
                UserStatus.ACTIVE, organization);
        String adminToken = login(admin.getEmail());
        String analystToken = login(analyst.getEmail());
        assertEquals(401, loginStatus(activeLegacyCustomer.getEmail()));

        mockMvc.perform(get("/api/organizations/me/approval-requests")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content[0].displayName").value("Test User"))
                .andExpect(jsonPath("$.data.content[0].email").doesNotExist());

        mockMvc.perform(post("/api/organizations/me/approval-requests/{id}/approve", pendingAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("ACTIVE"))
                .andExpect(jsonPath("$.data.email").doesNotExist());
        assertEquals(UserStatus.ACTIVE, pendingAnalyst.getStatus());

        mockMvc.perform(post("/api/organizations/me/users/{id}/suspend", analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("SUSPENDED"));
        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isUnauthorized());
        assertEquals(401, loginStatus(analyst.getEmail()));

        mockMvc.perform(post("/api/organizations/me/users/{id}/restore", analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("ACTIVE"));
        assertEquals(200, loginStatus(analyst.getEmail()));

        mockMvc.perform(post("/api/organizations/me/users/{id}/deactivate", analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("DISABLED"));
        assertTrue(userRepository.findById(analyst.getId()).isPresent());
        mockMvc.perform(post("/api/organizations/me/users/{id}/restore", analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isConflict());
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "USER_SUSPENDED".equals(event.getEventType())
                        && event.getActor().getId().equals(admin.getId())
                        && !event.getMessage().contains("reason")));
    }

    @Test
    void organizationAdminCannotManageAdministratorsOrUsersInAnotherTenant() throws Exception {
        Organization organization = approvedOrganization("Current Tenant");
        User admin = createUser("current-admin@example.com", RoleName.ADMIN, UserStatus.ACTIVE, organization);
        Organization otherOrganization = approvedOrganization("Other Tenant");
        User otherAnalyst = createUser("other-analyst@example.com", RoleName.SECURITY_ANALYST,
                UserStatus.ACTIVE, otherOrganization);
        User superAdmin = createUser("root@example.com", RoleName.SUPER_ADMIN, UserStatus.ACTIVE, null);
        String token = login(admin.getEmail());

        mockMvc.perform(post("/api/organizations/me/users/{id}/suspend", otherAnalyst.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/organizations/me/users/{id}/suspend", admin.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/organizations/me/users/{id}/suspend", superAdmin.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest());
    }

    @Test
    void superAdminCanManageEligibleAdminsButCannotRemoveLastActiveAdmin() throws Exception {
        Organization organization = approvedOrganization("Admin Management");
        User admin = createUser("managed-admin@example.com", RoleName.ADMIN, UserStatus.ACTIVE, organization);
        User otherAdmin = createUser("second-admin@example.com", RoleName.ADMIN, UserStatus.ACTIVE, organization);
        User superAdmin = createUser("platform-admin@example.com", RoleName.SUPER_ADMIN, UserStatus.ACTIVE, null);
        String token = login(superAdmin.getEmail());

        mockMvc.perform(get("/api/organizations/admin-accounts")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content[0].displayName").value("Test User"))
                .andExpect(jsonPath("$.data.content[0].email").doesNotExist());

        mockMvc.perform(post("/api/organizations/admin-accounts/{id}/suspend", admin.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("SUSPENDED"));
        mockMvc.perform(post("/api/organizations/admin-accounts/{id}/deactivate", otherAdmin.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isConflict());
        assertEquals(UserStatus.ACTIVE, otherAdmin.getStatus());
        mockMvc.perform(post("/api/organizations/admin-accounts/{id}/restore", admin.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void superAdminRegistrySeparatesOwnAndOtherApprovedOrganizations() throws Exception {
        Organization own = approvedOrganization("Own Approved Tenant");
        Organization pending = organization("Pending Tenant", OrganizationStatus.PENDING);
        Organization rejected = organization("Rejected Tenant", OrganizationStatus.REJECTED);
        Organization other = approvedOrganization("Other Approved Tenant");
        User ownAdmin = createUser("own-admin@example.com", RoleName.ADMIN, UserStatus.ACTIVE, own);
        own.setRegistrationAdmin(ownAdmin);
        organizationRepository.save(own);
        User otherAdmin = createUser("other-admin@example.com", RoleName.ADMIN, UserStatus.ACTIVE, other);
        other.setRegistrationAdmin(otherAdmin);
        organizationRepository.save(other);
        User superAdmin = createUser("registry-super@example.com", RoleName.SUPER_ADMIN, UserStatus.ACTIVE, own);

        mockMvc.perform(get("/api/organizations/registry")
                        .header("Authorization", "Bearer " + login(superAdmin.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.ownOrganization.id").value(own.getId()))
                .andExpect(jsonPath("$.data.ownOrganization.ownOrganization").value(true))
                .andExpect(jsonPath("$.data.ownOrganization.adminDisplayName").value("Test User"))
                .andExpect(jsonPath("$.data.approvedOrganizations.length()").value(1))
                .andExpect(jsonPath("$.data.approvedOrganizations[0].id").value(other.getId()))
                .andExpect(jsonPath("$.data.approvedOrganizations[0].ownOrganization").value(false))
                .andExpect(jsonPath("$.data.approvedOrganizations[0].name").value("Other Approved Tenant"))
                .andExpect(jsonPath("$.data.approvedOrganizations[0].registrationAdminEmail").doesNotExist())
                .andExpect(jsonPath("$.data.approvedOrganizations[0].password").doesNotExist());

        assertNotEquals(pending.getId(), other.getId());
        assertNotEquals(rejected.getId(), other.getId());
        mockMvc.perform(get("/api/organizations/{id}/members", other.getId())
                        .header("Authorization", "Bearer " + login(superAdmin.getEmail())))
                .andExpect(status().isForbidden());
    }

    @Test
    void unassociatedSuperAdminHasNoOwnOrganizationAndOtherRolesCannotViewRegistry() throws Exception {
        Organization approved = approvedOrganization("Visible Tenant");
        User superAdmin = createUser("unassociated-super@example.com", RoleName.SUPER_ADMIN,
                UserStatus.ACTIVE, null);
        mockMvc.perform(get("/api/organizations/registry")
                        .header("Authorization", "Bearer " + login(superAdmin.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.ownOrganization").value(org.hamcrest.Matchers.nullValue()))
                .andExpect(jsonPath("$.data.approvedOrganizations.length()").value(1))
                .andExpect(jsonPath("$.data.approvedOrganizations[0].id").value(approved.getId()));

        for (RoleName role : new RoleName[]{RoleName.ADMIN, RoleName.SECURITY_ANALYST}) {
            Organization organization = approvedOrganization("Denied " + role.name());
            User user = createUser("registry-" + role.name().toLowerCase() + "@example.com",
                    role, UserStatus.ACTIVE, organization);
            mockMvc.perform(get("/api/organizations/registry")
                            .header("Authorization", "Bearer " + login(user.getEmail())))
                    .andExpect(status().isForbidden());
        }
        mockMvc.perform(get("/api/organizations/registry")).andExpect(status().isUnauthorized());
    }

    @Test
    void superAdminSoftDeletesOrganizationWithoutRemovingUsersOrAuditHistory() throws Exception {
        Organization organization = approvedOrganization("Delete Eligible Tenant");
        User superAdmin = createUser("delete-super@example.com", RoleName.SUPER_ADMIN, UserStatus.ACTIVE, null);
        User member = createUser("delete-member@example.com", RoleName.SECURITY_ANALYST,
                UserStatus.ACTIVE, organization);
        String memberToken = login(member.getEmail());
        String superToken = login(superAdmin.getEmail());
        long existingAuditCount = auditEventRepository.count();

        mockMvc.perform(delete("/api/organizations/{id}", organization.getId())
                        .header("Authorization", "Bearer " + superToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.id").value(organization.getId()))
                .andExpect(jsonPath("$.data.status").value("DELETED"))
                .andExpect(jsonPath("$.data.email").doesNotExist());

        assertEquals(OrganizationStatus.DELETED,
                organizationRepository.findById(organization.getId()).orElseThrow().getStatus());
        assertTrue(userRepository.findById(member.getId()).isPresent());
        assertEquals(organization.getId(),
                userRepository.findById(member.getId()).orElseThrow().getOrganization().getId());
        assertEquals(401, loginStatus(member.getEmail()));
        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + memberToken))
                .andExpect(status().isUnauthorized());
        assertTrue(auditEventRepository.count() > existingAuditCount);
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "ORGANIZATION_DELETED".equals(event.getEventType())
                        && event.getOrganization().getId().equals(organization.getId())
                        && event.getActor().getId().equals(superAdmin.getId())
                        && !event.getMessage().contains("reason")));
    }

    @Test
    void deletionRejectsOwnOrganizationActiveSuperAdminAndMissingOrganizations() throws Exception {
        Organization own = approvedOrganization("Protected Own Tenant");
        User ownSuperAdmin = createUser("own-super@example.com", RoleName.SUPER_ADMIN,
                UserStatus.ACTIVE, own);
        String ownToken = login(ownSuperAdmin.getEmail());
        mockMvc.perform(delete("/api/organizations/{id}", own.getId())
                        .header("Authorization", "Bearer " + ownToken))
                .andExpect(status().isConflict());
        assertEquals(OrganizationStatus.APPROVED, own.getStatus());

        Organization protectedOrganization = approvedOrganization("Another Super Tenant");
        createUser("another-super@example.com", RoleName.SUPER_ADMIN,
                UserStatus.ACTIVE, protectedOrganization);
        User platformSuperAdmin = createUser("platform-super@example.com", RoleName.SUPER_ADMIN,
                UserStatus.ACTIVE, null);
        mockMvc.perform(delete("/api/organizations/{id}", protectedOrganization.getId())
                        .header("Authorization", "Bearer " + login(platformSuperAdmin.getEmail())))
                .andExpect(status().isConflict());
        assertEquals(OrganizationStatus.APPROVED, protectedOrganization.getStatus());

        mockMvc.perform(delete("/api/organizations/{id}", 999999L)
                        .header("Authorization", "Bearer " + login(platformSuperAdmin.getEmail())))
                .andExpect(status().isNotFound());
    }

    @Test
    void onlySuperAdminCanDeactivateAnOrganization() throws Exception {
        Organization organization = approvedOrganization("Role-Protected Tenant");
        for (RoleName role : new RoleName[]{RoleName.ADMIN, RoleName.SECURITY_ANALYST}) {
            User user = createUser("delete-denied-" + role.name().toLowerCase() + "@example.com",
                    role, UserStatus.ACTIVE, organization);
            mockMvc.perform(delete("/api/organizations/{id}", organization.getId())
                            .header("Authorization", "Bearer " + login(user.getEmail())))
                    .andExpect(status().isForbidden());
        }
        mockMvc.perform(delete("/api/organizations/{id}", organization.getId()))
                .andExpect(status().isUnauthorized());
        assertEquals(OrganizationStatus.APPROVED,
                organizationRepository.findById(organization.getId()).orElseThrow().getStatus());
    }

    private int loginStatus(String email) throws Exception {
        return mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andReturn().getResponse().getStatus();
    }

    private String login(String email) throws Exception {
        String body = mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        JsonNode response = objectMapper.readTree(body);
        return response.path("data").path("token").asText();
    }

    private Organization approvedOrganization(String name) {
        return organization(name, OrganizationStatus.APPROVED);
    }

    private Organization organization(String name, OrganizationStatus status) {
        Organization organization = new Organization();
        organization.setName(name);
        organization.setContactEmail("contact@example.com");
        organization.setPrimaryContactName("Tenant Owner");
        organization.setStatus(status);
        return organizationRepository.save(organization);
    }

    private User createUser(String email, RoleName roleName, UserStatus status, Organization organization) {
        User user = new User();
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(PASSWORD));
        user.setStatus(status);
        user.setOrganization(organization);
        Role role = roleRepository.findByName(roleName)
                .orElseGet(() -> roleRepository.save(new Role(roleName)));
        user.setRoles(Set.of(role));
        return userRepository.save(user);
    }
}
