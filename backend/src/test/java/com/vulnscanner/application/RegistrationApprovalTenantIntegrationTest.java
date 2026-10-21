package com.vulnscanner.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.audit.AuditEventRepository;
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

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class RegistrationApprovalTenantIntegrationTest {
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
    void registrationRejectsSuperAdminAndForgedStateButCreatesPendingAdminApplication() throws Exception {
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson("super@example.com", "SUPER_ADMIN", null, "Acme")))
                .andExpect(status().isBadRequest());
        assertFalse(userRepository.existsByEmail("super@example.com"));
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson("customer@example.com", "CUSTOMER", null, null)))
                .andExpect(status().isBadRequest());
        assertFalse(userRepository.existsByEmail("customer@example.com"));

        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Ada","lastName":"Admin","email":"ada@example.com",
                                 "password":"SecurePassword123!","role":"ADMIN","organizationName":"Acme",
                                 "status":"ACTIVE","approved":true,"organizationId":23}
                                """))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Ada","lastName":"Admin","email":"ada@example.com",
                                 "password":"SecurePassword123!","role":"ADMIN","organizationName":"Acme"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.email").value("ada@example.com"));

        User adminApplicant = userRepository.findByEmail("ada@example.com").orElseThrow();
        assertEquals(UserStatus.PENDING_APPROVAL, adminApplicant.getStatus());
        assertEquals(Set.of(RoleName.ADMIN), adminApplicant.getRoles().stream().map(Role::getName).collect(java.util.stream.Collectors.toSet()));
        Organization pendingOrganization = adminApplicant.getOrganization();
        assertEquals(OrganizationStatus.PENDING, pendingOrganization.getStatus());
        assertEquals(adminApplicant.getId(), pendingOrganization.getRegistrationAdmin().getId());
        assertEquals(401, loginStatus("ada@example.com"));
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "ORGANIZATION_ADMIN_REGISTRATION_SUBMITTED".equals(event.getEventType())
                        && event.getActor() != null
                        && event.getActor().getId().equals(adminApplicant.getId())));
    }

    @Test
    void onlySuperAdminCanApproveAndApprovalActivatesOnlyTheSubmittedAdministrator() throws Exception {
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson("ada@example.com", "ADMIN", null, "Acme")))
                .andExpect(status().isCreated());
        User applicant = userRepository.findByEmail("ada@example.com").orElseThrow();
        Organization org = applicant.getOrganization();
        User otherAdmin = createUser(RoleName.ADMIN, "other-admin@example.com", approvedOrganization("Other"));

        mockMvc.perform(post("/api/organizations/{id}/approve", org.getId())
                        .header("Authorization", "Bearer " + login(otherAdmin.getEmail())))
                .andExpect(status().isForbidden());
        assertEquals(OrganizationStatus.PENDING, org.getStatus());
        assertEquals(UserStatus.PENDING_APPROVAL, applicant.getStatus());

        User superAdmin = createUser(RoleName.SUPER_ADMIN, "super@example.com", null);
        String superToken = login(superAdmin.getEmail());
        mockMvc.perform(get("/api/organizations/pending").header("Authorization", "Bearer " + superToken))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/organizations/{id}/approve", org.getId())
                        .header("Authorization", "Bearer " + superToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("APPROVED"));
        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + superToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accountStatus").value("ACTIVE"))
                .andExpect(jsonPath("$.data.roles").value(contains("SUPER_ADMIN")))
                .andExpect(jsonPath("$.data.organizationId").value(nullValue()))
                .andExpect(jsonPath("$.data.organizationStatus").value(nullValue()))
                .andExpect(jsonPath("$.data.membershipApprovalStatus").value(nullValue()));
        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + login(otherAdmin.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accountStatus").value("ACTIVE"))
                .andExpect(jsonPath("$.data.organizationId").value(otherAdmin.getOrganization().getId()))
                .andExpect(jsonPath("$.data.organizationStatus").value("APPROVED"))
                .andExpect(jsonPath("$.data.roles").value(contains("ADMIN")))
                .andExpect(jsonPath("$.data.membershipApprovalStatus").value(nullValue()));

        assertEquals(OrganizationStatus.APPROVED, org.getStatus());
        assertEquals(UserStatus.ACTIVE, applicant.getStatus());
        assertEquals(UserStatus.ACTIVE, otherAdmin.getStatus());
        assertEquals(200, loginStatus("ada@example.com"));
        assertNull(superAdmin.getOrganization());
        mockMvc.perform(get("/api/organizations/{id}/members", org.getId())
                        .header("Authorization", "Bearer " + superToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void analystRegistersByApprovedOrganizationNameAndOnlyThatOrganizationsAdminCanApprove() throws Exception {
        Organization org = approvedOrganization("Analyst Tenant");
        Organization otherOrg = approvedOrganization("Other Tenant");
        User admin = createUser(RoleName.ADMIN, "tenant-admin@example.com", org);
        User otherAdmin = createUser(RoleName.ADMIN, "other-tenant-admin@example.com", otherOrg);

        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Test","lastName":"Unknown","email":"unknown@example.com",
                                 "password":"SecurePassword123!","role":"SECURITY_ANALYST",
                                 "organizationName":"Not An Organization"}
                                """))
                .andExpect(status().isBadRequest());
        assertFalse(userRepository.existsByEmail("unknown@example.com"));

        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Test","lastName":"User","email":"analyst@example.com",
                                 "password":"SecurePassword123!","role":"SECURITY_ANALYST",
                                 "organizationName":"  analyst tenant  "}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.email").value("analyst@example.com"));
        User analyst = userRepository.findByEmail("analyst@example.com").orElseThrow();
        assertEquals(UserStatus.PENDING_APPROVAL, analyst.getStatus());
        assertTrue(analyst.getRoles().stream().anyMatch(role -> role.getName() == RoleName.SECURITY_ANALYST));
        assertEquals(org.getId(), analyst.getOrganization().getId());
        assertEquals(401, loginStatus(analyst.getEmail()));
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized());
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "ORGANIZATION_MEMBERSHIP_REQUESTED".equals(event.getEventType())
                        && event.getTargetUser() != null && event.getTargetUser().getId().equals(analyst.getId())
                        && event.getOrganization() != null && event.getOrganization().getId().equals(org.getId())));
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Duplicate","lastName":"Analyst","email":"analyst@example.com",
                                 "password":"SecurePassword123!","role":"SECURITY_ANALYST",
                                 "organizationName":"Analyst Tenant"}
                                """))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Forged","lastName":"Role","email":"forged@example.com",
                                 "password":"SecurePassword123!","role":"SUPER_ADMIN",
                                 "organizationName":"Analyst Tenant"}
                                """))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Forged","lastName":"Tenant","email":"forged-tenant@example.com",
                                 "password":"SecurePassword123!","role":"SECURITY_ANALYST",
                                 "organizationName":"Analyst Tenant","organizationId":%d}
                                """.formatted(otherOrg.getId())))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Forged","lastName":"Approval","email":"forged-approval@example.com",
                                 "password":"SecurePassword123!","role":"SECURITY_ANALYST",
                                 "organizationName":"Analyst Tenant","status":"ACTIVE","approved":true}
                                """))
                .andExpect(status().isBadRequest());

        String adminToken = login(admin.getEmail());
        mockMvc.perform(post("/api/organizations/{organizationId}/membership-requests/{userId}/approve",
                        otherOrg.getId(), analyst.getId())
                        .header("Authorization", "Bearer " + login(otherAdmin.getEmail())))
                .andExpect(status().isBadRequest());
        assertEquals(UserStatus.PENDING_APPROVAL, analyst.getStatus());

        mockMvc.perform(get("/api/organizations/{organizationId}/membership-requests", org.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].displayName").value("Test User"))
                .andExpect(jsonPath("$.data[0].email").doesNotExist());
        mockMvc.perform(post("/api/organizations/{organizationId}/membership-requests/{userId}/approve",
                        org.getId(), analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("ACTIVE"));
        assertEquals(UserStatus.ACTIVE, analyst.getStatus());
        assertTrue(analyst.getRoles().stream().anyMatch(role -> role.getName() == RoleName.SECURITY_ANALYST));
        String analystToken = login(analyst.getEmail());
        assertEquals(200, loginStatus(analyst.getEmail()));
        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accountStatus").value("ACTIVE"))
                .andExpect(jsonPath("$.data.membershipApprovalStatus").value("APPROVED"))
                .andExpect(jsonPath("$.data.organizationId").value(org.getId()))
                .andExpect(jsonPath("$.data.organizationName").value("Analyst Tenant"))
                .andExpect(jsonPath("$.data.organizationStatus").value("APPROVED"))
                .andExpect(jsonPath("$.data.roles").value(contains("SECURITY_ANALYST")))
                .andExpect(jsonPath("$.data.password").doesNotExist())
                .andExpect(jsonPath("$.data.passwordHash").doesNotExist());
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "ANALYST_MEMBERSHIP_APPROVED".equals(event.getEventType())
                        && event.getOrganization() != null && event.getOrganization().getId().equals(org.getId())
                        && event.getActor() != null && event.getActor().getId().equals(admin.getId())));

        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Rejected","lastName":"Analyst","email":"rejected-analyst@example.com",
                                 "password":"SecurePassword123!","role":"SECURITY_ANALYST",
                                 "organizationName":"Analyst Tenant"}
                                """))
                .andExpect(status().isCreated());
        User rejectedAnalyst = userRepository.findByEmail("rejected-analyst@example.com").orElseThrow();
        mockMvc.perform(post("/api/organizations/{organizationId}/membership-requests/{userId}/reject",
                        org.getId(), rejectedAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("DISABLED"));
        assertEquals(401, loginStatus(rejectedAnalyst.getEmail()));
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "ANALYST_MEMBERSHIP_REJECTED".equals(event.getEventType())
                        && event.getActor() != null && event.getActor().getId().equals(admin.getId())));

        mockMvc.perform(get("/api/organizations/{organizationId}/members", otherOrg.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/organizations/me/invitations")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"invite@example.com\",\"role\":\"SECURITY_ANALYST\"}"))
                .andExpect(status().isNotFound());
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Legacy","lastName":"Role","email":"legacy-customer@example.com",
                                 "password":"SecurePassword123!","role":"CUSTOMER",
                                 "organizationName":"Analyst Tenant"}
                                """))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Legacy","lastName":"Token","email":"legacy-token@example.com",
                                 "password":"SecurePassword123!","role":"SECURITY_ANALYST",
                                 "organizationName":"Analyst Tenant","invitationToken":"not-accepted"}
                                """))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/organizations/{organizationId}/membership-requests/{userId}/approve",
                        org.getId(), rejectedAnalyst.getId())
                        .header("Authorization", "Bearer " + login(analyst.getEmail())))
                .andExpect(status().isForbidden());
    }

    @Test
    void analystRegistrationRejectsUnapprovedAndAmbiguousOrganizations() throws Exception {
        organizationRepository.save(organization("Waiting Org", OrganizationStatus.PENDING));
        organizationRepository.save(organization("Rejected Org", OrganizationStatus.REJECTED));
        organizationRepository.save(organization("Suspended Org", OrganizationStatus.SUSPENDED));
        organizationRepository.save(organization("Deleted Org", OrganizationStatus.DELETED));
        organizationRepository.save(organization("Ambiguous Org", OrganizationStatus.APPROVED));
        organizationRepository.save(organization(" ambiguous org ", OrganizationStatus.APPROVED));

        String[][] invalidOrganizations = {
                {"Waiting Org", "waiting@example.com"},
                {"Rejected Org", "rejected-org@example.com"},
                {"Suspended Org", "suspended-org@example.com"},
                {"Deleted Org", "deleted-org@example.com"},
                {"Missing Org", "missing@example.com"}
        };
        for (String[] candidate : invalidOrganizations) {
            String name = candidate[0];
            String email = candidate[1];
            mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"firstName":"Test","lastName":"Analyst","email":"%s",
                                     "password":"SecurePassword123!","role":"SECURITY_ANALYST",
                                     "organizationName":"%s"}
                                    """.formatted(email, name)))
                    .andExpect(status().isBadRequest());
            assertFalse(userRepository.existsByEmail(email));
        }
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"firstName":"Test","lastName":"Analyst","email":"ambiguous@example.com",
                                 "password":"SecurePassword123!","role":"SECURITY_ANALYST",
                                 "organizationName":"AMBIGUOUS ORG"}
                                """))
                .andExpect(status().isBadRequest());
        assertFalse(userRepository.existsByEmail("ambiguous@example.com"));
    }

    @Test
    void superAdminRegistryShowsApprovedOwaspOrganizationAfterApproval() throws Exception {
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson("owasp-admin@example.com", "ADMIN", null, "OWASP")))
                .andExpect(status().isCreated());
        User applicant = userRepository.findByEmail("owasp-admin@example.com").orElseThrow();
        User superAdmin = createUser(RoleName.SUPER_ADMIN, "registry-super@example.com", null);
        String superToken = login(superAdmin.getEmail());

        mockMvc.perform(post("/api/organizations/{id}/approve", applicant.getOrganization().getId())
                        .header("Authorization", "Bearer " + superToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("APPROVED"));

        mockMvc.perform(get("/api/organizations/registry").header("Authorization", "Bearer " + superToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.approvedOrganizations.length()").value(1))
                .andExpect(jsonPath("$.data.approvedOrganizations[0].name").value("OWASP"))
                .andExpect(jsonPath("$.data.approvedOrganizations[0].status").value("APPROVED"))
                .andExpect(jsonPath("$.data.approvedOrganizations[0].id")
                        .value(applicant.getOrganization().getId()))
                .andExpect(jsonPath("$.data.approvedOrganizations[0].findings").doesNotExist());
    }

    @Test
    void superAdminProfileShowsNoInventedOrganizationOrMembershipStatus() throws Exception {
        User superAdmin = createUser(RoleName.SUPER_ADMIN, "profile-super@example.com", null);
        mockMvc.perform(get("/api/users/me")
                        .header("Authorization", "Bearer " + login(superAdmin.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accountStatus").value("ACTIVE"))
                .andExpect(jsonPath("$.data.organizationId").value(nullValue()))
                .andExpect(jsonPath("$.data.organizationName").value(nullValue()))
                .andExpect(jsonPath("$.data.membershipApprovalStatus").value(nullValue()))
                .andExpect(jsonPath("$.data.password").doesNotExist());
    }

    @Test
    void rejectionAndSuspensionImmediatelyRevokeAccessForExistingTokens() throws Exception {
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson("rejected@example.com", "ADMIN", null, "Reject Co")))
                .andExpect(status().isCreated());
        User rejectedApplicant = userRepository.findByEmail("rejected@example.com").orElseThrow();
        User superAdmin = createUser(RoleName.SUPER_ADMIN, "super@example.com", null);
        String superToken = login(superAdmin.getEmail());

        mockMvc.perform(post("/api/organizations/{id}/reject", rejectedApplicant.getOrganization().getId())
                        .header("Authorization", "Bearer " + superToken))
                .andExpect(status().isOk());
        assertEquals(OrganizationStatus.REJECTED, rejectedApplicant.getOrganization().getStatus());
        assertEquals(UserStatus.DISABLED, rejectedApplicant.getStatus());
        assertEquals(401, loginStatus(rejectedApplicant.getEmail()));

        Organization activeOrg = approvedOrganization("Suspend Tenant");
        User admin = createUser(RoleName.ADMIN, "suspend-admin@example.com", activeOrg);
        String existingAdminToken = login(admin.getEmail());
        mockMvc.perform(post("/api/organizations/{id}/suspend", activeOrg.getId())
                        .header("Authorization", "Bearer " + superToken))
                .andExpect(status().isOk());
        assertEquals(OrganizationStatus.SUSPENDED, activeOrg.getStatus());
        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + existingAdminToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void publicOrganizationCreationAndUnauthenticatedProtectedRequestsAreDenied() throws Exception {
        mockMvc.perform(post("/api/organizations/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Public Org\",\"contactEmail\":\"org@example.com\",\"primaryContactName\":\"Ops\"}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/users/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void registrationAcceptsEightCharacterPassword() throws Exception {
        String password = "Pass1234";
        String request = """
        {"firstName":"Eight","lastName":"Characters","email":"eight@example.com",
         "password":"Pass1234","role":"ADMIN","organizationName":"Eight Character Org"}
        """;

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(request))
        .andExpect(status().isCreated());

        User registered = userRepository.findByEmail("eight@example.com").orElseThrow();
        assertEquals(UserStatus.PENDING_APPROVAL, registered.getStatus());
        assertTrue(passwordEncoder.matches(password, registered.getPassword()));
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

    private String registrationJson(String email, String role, Long organizationId, String organizationName) {
        String orgId = organizationId == null ? "" : ",\"organizationId\":" + organizationId;
        String orgName = organizationName == null ? "" : ",\"organizationName\":\"" + organizationName + "\"";
        return "{\"firstName\":\"Test\",\"lastName\":\"User\",\"email\":\"" + email
                + "\",\"password\":\"" + PASSWORD + "\",\"role\":\"" + role + "\"" + orgId + orgName + "}";
    }

    private Organization approvedOrganization(String name) {
        Organization organization = new Organization();
        organization.setName(name);
        organization.setContactEmail("contact-" + name.replace(" ", "").toLowerCase() + "@example.com");
        organization.setPrimaryContactName("Tenant Owner");
        organization.setStatus(OrganizationStatus.APPROVED);
        return organizationRepository.save(organization);
    }

    private Organization organization(String name, OrganizationStatus status) {
        Organization organization = new Organization();
        organization.setName(name);
        organization.setContactEmail("contact-" + name.trim().replace(" ", "").toLowerCase() + "@example.com");
        organization.setPrimaryContactName("Tenant Owner");
        organization.setStatus(status);
        return organizationRepository.save(organization);
    }

    private User createUser(RoleName roleName, String email, Organization organization) {
        User user = new User();
        user.setFirstName("Test");
        user.setLastName(roleName.name());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(PASSWORD));
        user.setStatus(UserStatus.ACTIVE);
        user.setOrganization(organization);
        user.setRoles(Set.of(roleRepository.findByName(roleName).orElseThrow()));
        return userRepository.save(user);
    }
}
