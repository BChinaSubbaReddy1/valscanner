package com.vulnscanner.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.scan.*;
import com.vulnscanner.application.target.*;
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
class ScanManagementIntegrationTest {
    private static final String PASSWORD = "SecurePassword123!";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private OrganizationRepository organizationRepository;
    @Autowired private TargetRepository targetRepository;
    @Autowired private ScanJobRepository scanJobRepository;
    @Autowired private ScanCrawlPageRepository scanCrawlPageRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    @BeforeEach
    void initializeRoles() {
        for (RoleName name : new RoleName[]{RoleName.SUPER_ADMIN, RoleName.ADMIN, RoleName.SECURITY_ANALYST}) {
            roleRepository.findByName(name).orElseGet(() -> roleRepository.save(new Role(name)));
        }
    }

    @Test
    void approvedAdminAndAnalystCanCreateAndReadOnlySameOrganizationJobs() throws Exception {
        Organization organization = approvedOrganization("Scan Tenant");
        Organization otherOrganization = approvedOrganization("Other Scan Tenant");
        User admin = createUser(RoleName.ADMIN, "scan-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "scan-analyst@example.com", organization);
        User otherAdmin = createUser(RoleName.ADMIN, "other-scan-admin@example.com", otherOrganization);
        User superAdmin = createUser(RoleName.SUPER_ADMIN, "scan-super@example.com", null);
        Target approvedTarget = createTarget(organization, admin, TargetStatus.APPROVED);
        Target pendingTarget = createTarget(organization, admin, TargetStatus.PENDING);
        Target foreignTarget = createTarget(otherOrganization, otherAdmin, TargetStatus.APPROVED);

        long analystScanId = createScan(login(analyst.getEmail()), approvedTarget.getId());
        long scanId = createScan(login(analyst.getEmail()), approvedTarget.getId());
        assertEquals(analyst.getId(), scanJobRepository.findById(analystScanId).orElseThrow()
                .getRequestedBy().getId());
        mockMvc.perform(get("/api/scans/{scanId}", scanId)
                        .header("Authorization", "Bearer " + login(analyst.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("PENDING_APPROVAL"));

        mockMvc.perform(get("/api/scans").header("Authorization", "Bearer " + login(analyst.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content.length()").value(2));

        mockMvc.perform(get("/api/scans/{scanId}", scanId)
                        .header("Authorization", "Bearer " + login(otherAdmin.getEmail())))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans").header("Authorization", "Bearer " + login(otherAdmin.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content.length()").value(0));

        mockMvc.perform(post("/api/scans").header("Authorization", "Bearer " + login(superAdmin.getEmail()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(scanRequest(approvedTarget.getId())))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/scans").header("Authorization", "Bearer " + login(admin.getEmail()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(scanRequest(pendingTarget.getId())))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/scans").header("Authorization", "Bearer " + login(admin.getEmail()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(scanRequest(foreignTarget.getId())))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/scans").header("Authorization", "Bearer " + login(admin.getEmail()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"targetId\":null,\"scanType\":\"PASSIVE_HEADERS\"}"))
                .andExpect(status().isBadRequest());
        assertEquals(2, scanJobRepository.count());
    }

    @Test
    void cancellationIsPersistedAndRepeatedCancellationIsRejected() throws Exception {
        Organization organization = approvedOrganization("Cancellation Tenant");
        User admin = createUser(RoleName.ADMIN, "cancel-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "cancel-analyst@example.com", organization);
        Target target = createTarget(organization, admin, TargetStatus.APPROVED);
        String token = login(analyst.getEmail());
        long scanId = createScan(token, target.getId());

        mockMvc.perform(post("/api/scans/{scanId}/cancel", scanId)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("CANCELLED"))
                .andExpect(jsonPath("$.data.cancellationRequested").value(true))
                .andExpect(jsonPath("$.data.completedAt").isNotEmpty());
        assertEquals(ScanStatus.CANCELLED, scanJobRepository.findById(scanId).orElseThrow().getStatus());

        mockMvc.perform(post("/api/scans/{scanId}/cancel", scanId)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isConflict());
    }

    @Test
    void analystRequestRequiresSameOrganizationAdminApproval() throws Exception {
        Organization organization = approvedOrganization("Approval Tenant");
        Organization otherOrganization = approvedOrganization("Other Approval Tenant");
        User admin = createUser(RoleName.ADMIN, "approval-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "approval-analyst@example.com", organization);
        User otherAdmin = createUser(RoleName.ADMIN, "other-approval-admin@example.com", otherOrganization);
        Target target = createTarget(organization, admin, TargetStatus.APPROVED);

        String analystToken = login(analyst.getEmail());
        String adminToken = login(admin.getEmail());
        String otherAdminToken = login(otherAdmin.getEmail());
        String response = mockMvc.perform(post("/api/scans")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(scanRequest(target.getId())))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.status").value("PENDING_APPROVAL"))
                .andReturn().getResponse().getContentAsString();
        long scanId = objectMapper.readTree(response).path("data").path("id").asLong();

        mockMvc.perform(get("/api/scans/pending-approval")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content.length()").value(1));
        mockMvc.perform(post("/api/scans/{scanId}/approve", scanId)
                        .header("Authorization", "Bearer " + otherAdminToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(post("/api/scans/{scanId}/reject", scanId)
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"not allowed\"}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/scans/{scanId}/reject", scanId)
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"testing rejection\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("REJECTED"))
                .andExpect(jsonPath("$.data.rejectionReason").value("testing rejection"));
        mockMvc.perform(post("/api/scans/{scanId}/approve", scanId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isConflict());
    }

    @Test
    void findingsAreEmptyOnlyAfterACompletedScanAndLifecycleRejectsInvalidTransitions() throws Exception {
        Organization organization = approvedOrganization("Findings Tenant");
        User admin = createUser(RoleName.ADMIN, "findings-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "findings-analyst@example.com", organization);
        Target target = createTarget(organization, admin, TargetStatus.APPROVED);
        String token = login(analyst.getEmail());
        long scanId = createScan(token, target.getId());
        ScanJob job = scanJobRepository.findById(scanId).orElseThrow();

        mockMvc.perform(get("/api/scans/{scanId}/findings", scanId).header("Authorization", "Bearer " + token))
                .andExpect(status().isConflict());

        assertThrows(IllegalStateException.class,
                () -> job.transitionTo(ScanStatus.COMPLETED, 100, "Completed", null));
        job.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        job.transitionTo(ScanStatus.RUNNING, 10, "Running", null);
        job.transitionTo(ScanStatus.COMPLETED, 100, "Completed", null);
        scanJobRepository.saveAndFlush(job);

        mockMvc.perform(get("/api/scans/{scanId}/findings", scanId).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(0));
    }

    @Test
    void crawlPagesAreReturnedOnlyForAnAuthorizedScan() throws Exception {
        Organization organization = approvedOrganization("Crawl Tenant");
        Organization otherOrganization = approvedOrganization("Other Crawl Tenant");
        User admin = createUser(RoleName.ADMIN, "crawl-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "crawl-analyst@example.com", organization);
        User otherAnalyst = createUser(RoleName.SECURITY_ANALYST, "other-crawl-analyst@example.com", otherOrganization);
        Target target = createTarget(organization, admin, TargetStatus.APPROVED);
        long scanId = createScan(login(analyst.getEmail()), target.getId());
        ScanJob job = scanJobRepository.findById(scanId).orElseThrow();
        scanCrawlPageRepository.saveAndFlush(new ScanCrawlPage(
                job, "https://example.org/", 0, 200, 128, 2));

        mockMvc.perform(get("/api/scans/{scanId}/crawl-pages", scanId)
                        .header("Authorization", "Bearer " + login(analyst.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].url").value("https://example.org/"))
                .andExpect(jsonPath("$.data[0].responseBytes").value(128));

        mockMvc.perform(get("/api/scans/{scanId}/crawl-pages", scanId)
                        .header("Authorization", "Bearer " + login(otherAnalyst.getEmail())))
                .andExpect(status().isNotFound());
    }

    @Test
    void failedLifecycleRequiresSafeReasonAndPersistsTerminalState() {
        Organization organization = approvedOrganization("Failure Tenant");
        User admin = createUser(RoleName.ADMIN, "failure-admin@example.com", organization);
        Target target = createTarget(organization, admin, TargetStatus.APPROVED);
        ScanJob job = scanJobRepository.save(new ScanJob(target, organization, admin, ScanType.PASSIVE_HEADERS));
        job.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Pending approval", null);
        job.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        job.transitionTo(ScanStatus.RUNNING, 5, "Running", null);

        assertThrows(IllegalArgumentException.class,
                () -> job.transitionTo(ScanStatus.FAILED, 5, "Failed", null));
        job.transitionTo(ScanStatus.FAILED, 5, "Execution failed", ScanFailureReason.EXECUTOR_UNAVAILABLE);
        scanJobRepository.saveAndFlush(job);

        ScanJob persisted = scanJobRepository.findById(job.getId()).orElseThrow();
        assertEquals(ScanStatus.FAILED, persisted.getStatus());
        assertEquals("EXECUTOR_UNAVAILABLE", persisted.getFailureReason());
        assertNotNull(persisted.getStartedAt());
        assertNotNull(persisted.getCompletedAt());
        assertThrows(IllegalStateException.class,
                () -> persisted.transitionTo(ScanStatus.RUNNING, 5, "Retry", null));
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

    private Target createTarget(Organization organization, User creator, TargetStatus status) {
        Target target = new Target();
        target.setName("Scan test target");
        target.setUrl("https://example.org");
        target.setType(TargetType.WEB_APPLICATION);
        target.setOrganization(organization);
        target.setCreatedBy(creator);
        target.setStatus(status);
        return targetRepository.save(target);
    }

    private long createScan(String token, Long targetId) throws Exception {
        String response = mockMvc.perform(post("/api/scans")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(scanRequest(targetId)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.scanType").value("PASSIVE_HEADERS"))
                .andExpect(jsonPath("$.data.status").value("PENDING_APPROVAL"))
                .andReturn().getResponse().getContentAsString();
        JsonNode json = objectMapper.readTree(response);
        return json.path("data").path("id").asLong();
    }

    private String scanRequest(Long targetId) throws Exception {
        return objectMapper.writeValueAsString(java.util.Map.of("targetId", targetId, "scanType", "PASSIVE_HEADERS"));
    }

    private String login(String email) throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(response).path("data").path("token").asText();
    }
}
