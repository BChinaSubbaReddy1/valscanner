package com.vulnscanner.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.auth.PasswordResetEmailService;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.target.Target;
import com.vulnscanner.application.target.TargetRepository;
import com.vulnscanner.application.target.TargetStatus;
import com.vulnscanner.application.target.TargetAnalystAssignmentRepository;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.mockito.Mockito.when;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class TargetManagementIntegrationTest {
    private static final String PASSWORD = "SecurePassword123!";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private OrganizationRepository organizationRepository;
    @Autowired private TargetRepository targetRepository;
    @Autowired private TargetAnalystAssignmentRepository assignmentRepository;
    @Autowired private AuditEventRepository auditEventRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @MockBean private PasswordResetEmailService passwordResetEmailService;

    @BeforeEach
    void initializeRoles() {
        when(passwordResetEmailService.isConfigured()).thenReturn(true);
        for (RoleName name : new RoleName[]{
                RoleName.SUPER_ADMIN, RoleName.ADMIN, RoleName.SECURITY_ANALYST}) {
            roleRepository.findByName(name).orElseGet(() -> roleRepository.save(new Role(name)));
        }
    }

    @Test
    void adminCreatesApprovesAndSoftDeletesTargetWithAuditHistory() throws Exception {
        Organization organization = approvedOrganization("Target Tenant");
        User admin = createUser(RoleName.ADMIN, "target-admin@example.com", organization);
        String token = login(admin.getEmail());

        String createdBody = mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"Public app","url":"https://example.org/app","type":"WEB_APPLICATION",
                                 "organizationId":9999}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.status").value("PENDING"))
                .andExpect(jsonPath("$.data.organizationId").value(organization.getId()))
                .andReturn().getResponse().getContentAsString();

        JsonNode createdJson = objectMapper.readTree(createdBody);
        long targetId = createdJson.path("data").path("id").asLong();
        assertEquals(1, targetRepository.count());
        assertEquals(1, auditEventRepository.count());

        mockMvc.perform(post("/api/targets/{id}/decision", targetId)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"decision\":\"APPROVE\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("APPROVED"));

        mockMvc.perform(delete("/api/targets/{id}", targetId)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("DELETED"));

        Target target = targetRepository.findById(targetId).orElseThrow();
        assertEquals(TargetStatus.DELETED, target.getStatus());
        assertEquals(3, auditEventRepository.count());
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "TARGET_DELETED".equals(event.getEventType())
                        && event.getOrganization().getId().equals(organization.getId())));
    }

    @Test
    void targetResponsesRedactQueryValuesWhileStoredTargetRemainsUsableForScanning() throws Exception {
        Organization organization = approvedOrganization("Target URL Tenant");
        User admin = createUser(RoleName.ADMIN, "target-url-admin@example.com", organization);
        String targetUrl = "https://example.org/app?token=target-secret&q=search-term";

        String response = mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + login(admin.getEmail()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(targetRequest("Query target", targetUrl)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.url").value("https://example.org/app?token&q"))
                .andReturn().getResponse().getContentAsString();

        assertFalse(response.contains("target-secret"));
        assertFalse(response.contains("search-term"));
        long targetId = objectMapper.readTree(response).path("data").path("id").asLong();
        assertEquals(targetUrl, targetRepository.findById(targetId).orElseThrow().getUrl());
    }

    @Test
    void analystsSeeOnlyIndividuallyAssignedApprovedTargets() throws Exception {
        Organization organization = approvedOrganization("Analyst Tenant");
        Organization otherOrganization = approvedOrganization("Other Target Tenant");
        User admin = createUser(RoleName.ADMIN, "analyst-target-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "target-analyst@example.com", organization);
        User otherAdmin = createUser(RoleName.ADMIN, "other-target-admin@example.com", otherOrganization);
        createUser(RoleName.SECURITY_ANALYST, "other-target-analyst@example.com", otherOrganization);
        Target pending = createTarget(organization, admin, "Pending target", TargetStatus.PENDING);
        Target approved = createTarget(organization, admin, "Approved target", TargetStatus.APPROVED);
        createTarget(otherOrganization, otherAdmin, "Foreign target", TargetStatus.APPROVED);

        String analystToken = login(analyst.getEmail());
        mockMvc.perform(get("/api/targets").header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(0));
        mockMvc.perform(get("/api/targets/{id}", approved.getId())
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isNotFound());

        String adminToken = login(admin.getEmail());
        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", approved.getId(), analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.analystId").value(analyst.getId()));

        mockMvc.perform(get("/api/targets/{id}", approved.getId())
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/targets/{id}", pending.getId())
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/targets").header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].id").value(approved.getId()));

        mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + login(analyst.getEmail()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(targetRequest("Analyst target", "https://example.org")))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminsManageOnlyApprovedSameOrganizationAnalystAssignmentsAndRevocationIsImmediate()
            throws Exception {
        Organization organization = approvedOrganization("Assignment Tenant");
        Organization otherOrganization = approvedOrganization("Foreign Assignment Tenant");
        User admin = createUser(RoleName.ADMIN, "assignment-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "assignment-analyst@example.com", organization);
        User unassignedAnalyst = createUser(RoleName.SECURITY_ANALYST,
                "unassigned-analyst@example.com", organization);
        User inactiveAnalyst = createUser(RoleName.SECURITY_ANALYST,
                "inactive-assignment-analyst@example.com", organization);
        inactiveAnalyst.setStatus(UserStatus.DISABLED);
        userRepository.saveAndFlush(inactiveAnalyst);
        User foreignAnalyst = createUser(RoleName.SECURITY_ANALYST,
                "foreign-assignment-analyst@example.com", otherOrganization);
        User privilegedAnalyst = createUser(RoleName.SECURITY_ANALYST,
                "privileged-assignment-analyst@example.com", organization);
        privilegedAnalyst.setRoles(Set.of(
                roleRepository.findByName(RoleName.SECURITY_ANALYST).orElseThrow(),
                roleRepository.findByName(RoleName.ADMIN).orElseThrow()));
        userRepository.saveAndFlush(privilegedAnalyst);
        createUser(RoleName.SUPER_ADMIN, "super-assignment-analyst@example.com", organization);
        User foreignAdmin = createUser(RoleName.ADMIN, "foreign-assignment-admin@example.com", otherOrganization);
        Target approved = createTarget(organization, admin, "Assign approved", TargetStatus.APPROVED);
        Target pending = createTarget(organization, admin, "Assign pending", TargetStatus.PENDING);
        Target foreign = createTarget(otherOrganization, foreignAdmin, "Foreign approved", TargetStatus.APPROVED);
        String adminToken = login(admin.getEmail());
        String analystToken = login(analyst.getEmail());
        String unassignedAnalystToken = login(unassignedAnalyst.getEmail());

        mockMvc.perform(get("/api/targets/assignment-analysts")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(2))
                .andExpect(jsonPath("$.data[0].displayName").value("Test User"))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("@example.com"))));
        mockMvc.perform(get("/api/targets/{targetId}/assignments", approved.getId())
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isForbidden());

        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", pending.getId(), analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isConflict());
        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", approved.getId(),
                        foreignAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", approved.getId(),
                        inactiveAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", approved.getId(),
                        privilegedAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", foreign.getId(), analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());

        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", approved.getId(), analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", approved.getId(), analyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
        assertEquals(1, assignmentRepository.count());
        mockMvc.perform(get("/api/targets/{targetId}/assignments", approved.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].displayName").value("Test User"));
        mockMvc.perform(get("/api/targets/{id}", approved.getId())
                        .header("Authorization", "Bearer " + unassignedAnalystToken))
                .andExpect(status().isNotFound());

        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", approved.getId(),
                        unassignedAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.analystId").value(unassignedAnalyst.getId()));
        assertEquals(1, assignmentRepository.count());
        mockMvc.perform(get("/api/targets/{id}", approved.getId())
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/targets/{id}", approved.getId())
                        .header("Authorization", "Bearer " + unassignedAnalystToken))
                .andExpect(status().isOk());
        mockMvc.perform(delete("/api/targets/{targetId}/assignments/{analystId}",
                        approved.getId(), unassignedAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/targets/{id}", approved.getId())
                        .header("Authorization", "Bearer " + unassignedAnalystToken))
                .andExpect(status().isNotFound());
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "TARGET_ANALYST_ASSIGNED".equals(event.getEventType())));
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "TARGET_ANALYST_ASSIGNMENT_REVOKED".equals(event.getEventType())));
    }

    @Test
    void existingAssignmentDoesNotGrantAccessAfterTargetIsDeleted() throws Exception {
        Organization organization = approvedOrganization("Deleted Assignment Tenant");
        User admin = createUser(RoleName.ADMIN, "deleted-assignment-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "deleted-assignment-analyst@example.com", organization);
        Target target = createTarget(organization, admin, "Deleted assigned target", TargetStatus.APPROVED);
        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", target.getId(), analyst.getId())
                        .header("Authorization", "Bearer " + login(admin.getEmail())))
                .andExpect(status().isOk());

        target.setStatus(TargetStatus.DELETED);
        targetRepository.saveAndFlush(target);
        String analystToken = login(analyst.getEmail());
        mockMvc.perform(get("/api/targets").header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(0));
        mockMvc.perform(get("/api/targets/{targetId}", target.getId())
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isNotFound());
    }

    @Test
    void targetIdsCannotBeUsedAcrossOrganizationsAndInvalidUrlCannotBeCreated() throws Exception {
        Organization firstOrganization = approvedOrganization("First Target Tenant");
        Organization secondOrganization = approvedOrganization("Second Target Tenant");
        User firstAdmin = createUser(RoleName.ADMIN, "first-target-admin@example.com", firstOrganization);
        User secondAdmin = createUser(RoleName.ADMIN, "second-target-admin@example.com", secondOrganization);
        Target target = createTarget(firstOrganization, firstAdmin, "Private target", TargetStatus.PENDING);
        String secondToken = login(secondAdmin.getEmail());

        mockMvc.perform(get("/api/targets/{id}", target.getId())
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("Private target"))));
        mockMvc.perform(post("/api/targets/{id}/decision", target.getId())
                        .header("Authorization", "Bearer " + secondToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"decision\":\"APPROVE\"}"))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("Private target"))));
        mockMvc.perform(delete("/api/targets/{id}", target.getId())
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("Private target"))));

        mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + secondToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(targetRequest("Bad URL", "javascript:alert(1)")))
                .andExpect(status().isBadRequest());
        assertEquals(TargetStatus.PENDING, targetRepository.findById(target.getId()).orElseThrow().getStatus());
    }

    @Test
    void adminCanRegisterUnlistedPublicHttpAndHttpsTargetsButNotInvalidPorts() throws Exception {
        Organization organization = approvedOrganization("Dynamic Public Targets");
        User admin = createUser(RoleName.ADMIN, "dynamic-public-target-admin@example.com", organization);
        String token = login(admin.getEmail());

        for (String url : Set.of("http://unlisted-http.public.example/app",
                "https://unlisted-https.public.example/app")) {
            mockMvc.perform(post("/api/targets")
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(targetRequest("Unlisted public site", url)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.data.url").value(url))
                    .andExpect(jsonPath("$.data.status").value("PENDING"));
        }

        mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(targetRequest("Bad port", "https://bad-port.public.example:70000/")))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(targetRequest("Empty port", "https://empty-port.public.example:/")))
                .andExpect(status().isBadRequest());
    }

    private Organization approvedOrganization(String name) {
        Organization organization = new Organization();
        organization.setName(name);
        organization.setContactEmail("ops@example.com");
        organization.setPrimaryContactName("Operations");
        organization.setStatus(OrganizationStatus.APPROVED);
        return organizationRepository.save(organization);
    }

    private User createUser(RoleName roleName, String email, Organization organization) {
        User user = new User();
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(PASSWORD));
        user.setStatus(UserStatus.ACTIVE);
        user.setOrganization(organization);
        user.setRoles(Set.of(roleRepository.findByName(roleName).orElseThrow()));
        return userRepository.save(user);
    }

    private Target createTarget(Organization organization, User creator, String name, TargetStatus status) {
        Target target = new Target();
        target.setName(name);
        target.setUrl("https://example.org/" + name.toLowerCase().replace(' ', '-'));
        target.setType(com.vulnscanner.application.target.TargetType.WEB_APPLICATION);
        target.setOrganization(organization);
        target.setCreatedBy(creator);
        target.setStatus(status);
        return targetRepository.save(target);
    }

    private String targetRequest(String name, String url) throws Exception {
        return objectMapper.writeValueAsString(java.util.Map.of(
                "name", name, "url", url, "type", "WEB_APPLICATION"));
    }

    private String login(String email) throws Exception {
        return LoginOtpTestSupport.completeLogin(
                mockMvc, objectMapper, passwordResetEmailService, email, PASSWORD);
    }
}
