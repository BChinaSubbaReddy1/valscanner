package com.vulnscanner.application;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.auth.PasswordResetEmailService;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.scan.DiscoveredForm;
import com.vulnscanner.application.scan.ScanCrawlPage;
import com.vulnscanner.application.scan.ScanCrawlPageRepository;
import com.vulnscanner.application.scan.ScanFailureReason;
import com.vulnscanner.application.scan.ScanFinding;
import com.vulnscanner.application.scan.ScanFindingRepository;
import com.vulnscanner.application.scan.ScanJob;
import com.vulnscanner.application.scan.ScanJobRepository;
import com.vulnscanner.application.scan.ScanStatus;
import com.vulnscanner.application.scan.ScanType;
import com.vulnscanner.application.target.Target;
import com.vulnscanner.application.target.TargetAnalystAssignment;
import com.vulnscanner.application.target.TargetAnalystAssignmentRepository;
import com.vulnscanner.application.target.TargetRepository;
import com.vulnscanner.application.target.TargetStatus;
import com.vulnscanner.application.target.TargetType;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;

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
    @Autowired private TargetAnalystAssignmentRepository assignmentRepository;
    @Autowired private ScanJobRepository scanJobRepository;
    @Autowired private ScanFindingRepository scanFindingRepository;
    @Autowired private ScanCrawlPageRepository scanCrawlPageRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @MockBean private PasswordResetEmailService passwordResetEmailService;

    @BeforeEach
    void initializeRoles() {
        when(passwordResetEmailService.isConfigured()).thenReturn(true);
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
        assignTarget(approvedTarget, analyst, admin);

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
    void historicalAnalyticsUsesPersistedRecordsAndEnforcesRoleAndAssignmentScope() throws Exception {
        Organization organization = approvedOrganization("Analytics Tenant");
        Organization foreignOrganization = approvedOrganization("Foreign Analytics Tenant");
        User admin = createUser(RoleName.ADMIN, "analytics-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "analytics-analyst@example.com", organization);
        User otherAnalyst = createUser(RoleName.SECURITY_ANALYST, "analytics-other@example.com", organization);
        User foreignAdmin = createUser(RoleName.ADMIN, "analytics-foreign-admin@example.com", foreignOrganization);
        User foreignAnalyst = createUser(RoleName.SECURITY_ANALYST, "analytics-foreign@example.com", foreignOrganization);
        User superAdmin = createUser(RoleName.SUPER_ADMIN, "analytics-super@example.com", null);

        Target assignedTarget = createTarget(organization, admin, TargetStatus.APPROVED);
        Target otherTarget = createTarget(organization, admin, TargetStatus.APPROVED);
        Target foreignTarget = createTarget(foreignOrganization, foreignAdmin, TargetStatus.APPROVED);
        assignTarget(assignedTarget, analyst, admin);
        assignTarget(otherTarget, otherAnalyst, admin);
        assignTarget(foreignTarget, foreignAnalyst, foreignAdmin);

        long assignedScanId = createScan(login(analyst.getEmail()), assignedTarget.getId());
        long otherScanId = createScan(login(otherAnalyst.getEmail()), otherTarget.getId());
        long foreignScanId = createScan(login(foreignAnalyst.getEmail()), foreignTarget.getId());
        ScanJob assignedScan = completeScan(assignedScanId);
        ScanJob otherScan = completeScan(otherScanId);
        ScanJob foreignScan = completeScan(foreignScanId);
        scanFindingRepository.saveAndFlush(new ScanFinding(assignedScan, "ASSIGNED_HIGH", "HIGH",
                "assigned-component", "assigned evidence", "reason", "fix", "TEST", "OBSERVED"));
        scanFindingRepository.saveAndFlush(new ScanFinding(otherScan, "OTHER_MEDIUM", "MEDIUM",
                "other-component", "other evidence", "reason", "fix", "TEST", "OBSERVED"));
        scanFindingRepository.saveAndFlush(new ScanFinding(foreignScan, "FOREIGN_LOW", "LOW",
                "foreign-component", "foreign evidence", "reason", "fix", "TEST", "OBSERVED"));

        mockMvc.perform(get("/api/scans/me/dashboard/analytics")
                        .param("days", "1")
                        .header("Authorization", "Bearer " + login(analyst.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.scope").value("ANALYST"))
                .andExpect(jsonPath("$.data.points.length()").value(1))
                .andExpect(jsonPath("$.data.points[0].scans").value(1))
                .andExpect(jsonPath("$.data.points[0].completedScans").value(1))
                .andExpect(jsonPath("$.data.points[0].highFindings").value(1))
                .andExpect(jsonPath("$.data.points[0].mediumFindings").value(0))
                .andExpect(jsonPath("$.data.points[0].lowFindings").value(0));

        mockMvc.perform(get("/api/organizations/me/dashboard/analytics")
                        .param("days", "1")
                        .header("Authorization", "Bearer " + login(admin.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.scope").value("ORGANIZATION"))
                .andExpect(jsonPath("$.data.points[0].scans").value(2))
                .andExpect(jsonPath("$.data.points[0].highFindings").value(1))
                .andExpect(jsonPath("$.data.points[0].mediumFindings").value(1))
                .andExpect(jsonPath("$.data.points[0].lowFindings").value(0));

        mockMvc.perform(get("/api/organizations/platform-dashboard/analytics")
                        .param("days", "1")
                        .header("Authorization", "Bearer " + login(superAdmin.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.scope").value("PLATFORM"))
                .andExpect(jsonPath("$.data.points[0].organizationsRegistered").value(2));

        mockMvc.perform(get("/api/scans/me/dashboard/analytics")
                        .header("Authorization", "Bearer " + login(admin.getEmail())))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/organizations/me/dashboard/analytics")
                        .param("days", "91")
                        .header("Authorization", "Bearer " + login(admin.getEmail())))
                .andExpect(status().isBadRequest());
    }

    @Test
    void scanAnalyticsAggregatePersistedEvidenceAndRespectAnalystAssignments() throws Exception {
        Organization organization = approvedOrganization("Link Analytics Tenant");
        User admin = createUser(RoleName.ADMIN, "link-analytics-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "link-analytics-analyst@example.com", organization);
        User unassignedAnalyst = createUser(
                RoleName.SECURITY_ANALYST, "link-analytics-unassigned@example.com", organization);
        Target target = createTarget(organization, admin, TargetStatus.APPROVED);
        assignTarget(target, analyst, admin);

        ScanJob previous = completedAnalyticsScan(target, analyst, admin, ScanType.ZAP_ACTIVE);
        scanFindingRepository.saveAndFlush(new ScanFinding(previous, "MISSING_STRICT_TRANSPORT_SECURITY",
                "MEDIUM", "https://example.org/login", "HSTS header was absent", "Header observation",
                "Configure HSTS", "PASSIVE_HEADERS", "OBSERVED",
                "https://example.org/login", "GET", null));
        ScanJob current = completedAnalyticsScan(target, analyst, admin, ScanType.ZAP_ACTIVE);
        current.updateZapActiveStatus("COMPLETED");
        current.recordZapRuleInventory("AVAILABLE",
                List.of("10001: passive rule"), List.of("20001: active rule"));
        scanJobRepository.saveAndFlush(current);
        scanFindingRepository.saveAndFlush(new ScanFinding(current, "MISSING_STRICT_TRANSPORT_SECURITY",
                "LOW", "https://example.org/login", "HSTS header was absent", "Header observation",
                "Configure HSTS", "PASSIVE_HEADERS", "OBSERVED",
                "https://example.org/login", "GET", null));
        scanFindingRepository.saveAndFlush(new ScanFinding(current, "MISSING_STRICT_TRANSPORT_SECURITY",
                "LOW", "https://example.org/login", "HSTS header was absent", "Header observation",
                "Configure HSTS", "OWASP_ZAP", "OBSERVED",
                "https://example.org/login", "GET", null));
        scanFindingRepository.saveAndFlush(new ScanFinding(current, "REFLECTED_XSS_POTENTIAL",
                "HIGH", "https://example.org/search?q", "Controlled reflection marker observed",
                "Response reflected a test marker", "Encode untrusted output", "OWASP_ZAP", "POTENTIAL",
                "https://example.org/search?q", "GET", "q"));
        scanCrawlPageRepository.saveAndFlush(new ScanCrawlPage(
                current, "https://example.org/login?token=analytics-secret", 0, 200, 512, 1));

        String analystToken = login(analyst.getEmail());
        String adminToken = login(admin.getEmail());
        String analyticsResponse = mockMvc.perform(get("/api/scans/{scanId}/analytics", current.getId())
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.targetId").value(target.getId()))
                .andExpect(jsonPath("$.data.totalFindings").value(2))
                .andExpect(jsonPath("$.data.rawFindingObservations").value(3))
                .andExpect(jsonPath("$.data.duplicateEngineObservationsSuppressed").value(1))
                .andExpect(jsonPath("$.data.totalCrawlPages").value(1))
                .andExpect(jsonPath("$.data.resultCompleteness").value("FULL"))
                .andExpect(jsonPath("$.data.endpoints.length()").value(3))
                .andExpect(jsonPath("$.data.owaspCategories[0].key").value("A03:2021 Injection"))
                .andExpect(jsonPath("$.data.unmappedOwaspFindings").value(0))
                .andExpect(jsonPath("$.data.ruleCoverage.inventoryStatus").value("AVAILABLE"))
                .andExpect(jsonPath("$.data.ruleCoverage.passiveEnabledRules[0]").value("10001: passive rule"))
                .andExpect(jsonPath("$.data.ruleCoverage.nativeRulesWithFindings.length()").value(1))
                .andExpect(jsonPath("$.data.ruleCoverage.zapRulesWithFindings.length()").value(2))
                .andExpect(jsonPath("$.data.history.previousScanId").value(previous.getId()))
                .andExpect(jsonPath("$.data.history.newFindings").value(1))
                .andExpect(jsonPath("$.data.history.severityChangedFindings").value(1))
                .andReturn().getResponse().getContentAsString();
        assertFalse(analyticsResponse.contains("analytics-secret"));
        assertFalse(analyticsResponse.contains("q=search"));

        mockMvc.perform(get("/api/scans/{scanId}/analytics", current.getId())
                        .header("Authorization", "Bearer " + login(unassignedAnalyst.getEmail())))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/{scanId}/report", current.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.analytics.totalFindings").value(2))
                .andExpect(jsonPath("$.data.analytics.history.previousScanId").value(previous.getId()));
        mockMvc.perform(get("/api/scans/{scanId}/report/export", current.getId())
                        .param("format", "csv")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Link-wise Endpoint Finding Counts")))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("analytics-secret"))));
        String pdf = new String(mockMvc.perform(get("/api/scans/{scanId}/report/export", current.getId())
                        .param("format", "pdf")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray(), java.nio.charset.StandardCharsets.ISO_8859_1);
        assertTrue(pdf.contains("Link-wise endpoint findings:"));
        assertFalse(pdf.contains("analytics-secret"));
    }

    @Test
    void cancellationIsPersistedAndRepeatedCancellationIsRejected() throws Exception {
        Organization organization = approvedOrganization("Cancellation Tenant");
        User admin = createUser(RoleName.ADMIN, "cancel-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "cancel-analyst@example.com", organization);
        Target target = createTarget(organization, admin, TargetStatus.APPROVED);
        assignTarget(target, analyst, admin);
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
        assignTarget(target, analyst, admin);

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
                .andExpect(jsonPath("$.data.rejectionReason").value("testing rejection"))
                .andExpect(jsonPath("$.data.executionSummary.zapRequested").value(true))
                .andExpect(jsonPath("$.data.executionSummary.zapFailureReason")
                        .value("SCAN_REJECTED_BEFORE_ZAP"));
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
        assignTarget(target, analyst, admin);
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
        assignTarget(target, analyst, admin);
        long scanId = createScan(login(analyst.getEmail()), target.getId());
        ScanJob job = scanJobRepository.findById(scanId).orElseThrow();
        scanCrawlPageRepository.saveAndFlush(new ScanCrawlPage(
                job, "https://example.org/page?token=page-secret&view=summary", 0, 200, 128, 2,
                List.of(new DiscoveredForm(
                        "https://example.org/search?session=action-secret&q=search-term", "GET", List.of("query")))));

        String crawlResponse = mockMvc.perform(get("/api/scans/{scanId}/crawl-pages", scanId)
                        .header("Authorization", "Bearer " + login(analyst.getEmail())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].url").value("https://example.org/page?token&view"))
                .andExpect(jsonPath("$.data[0].responseBytes").value(128))
                .andExpect(jsonPath("$.data[0].discoveredForms[0].actionUrl")
                        .value("https://example.org/search?session&q"))
                .andExpect(jsonPath("$.data[0].discoveredForms[0].method").value("GET"))
                .andExpect(jsonPath("$.data[0].discoveredForms[0].parameterNames[0]").value("query"))
                .andReturn().getResponse().getContentAsString();
        assertFalse(crawlResponse.contains("page-secret"));
        assertFalse(crawlResponse.contains("action-secret"));
        assertFalse(crawlResponse.contains("search-term"));
        ScanCrawlPage storedPage = scanCrawlPageRepository.findByScanJob_IdOrderByDepthAscUrlAsc(scanId).getFirst();
        assertFalse(storedPage.getUrl().contains("page-secret"));
        assertFalse(storedPage.getDiscoveredForms().getFirst().actionUrl().contains("action-secret"));

        mockMvc.perform(get("/api/scans/{scanId}/crawl-pages", scanId)
                        .header("Authorization", "Bearer " + login(otherAnalyst.getEmail())))
                .andExpect(status().isNotFound());
    }

    @Test
    void foreignOrganizationCannotReadOrMutateScanResourcesById() throws Exception {
        Organization organization = approvedOrganization("Scan Resource Tenant");
        Organization otherOrganization = approvedOrganization("Other Scan Resource Tenant");
        User admin = createUser(RoleName.ADMIN, "scan-resource-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "scan-resource-analyst@example.com", organization);
        User otherAdmin = createUser(RoleName.ADMIN, "other-scan-resource-admin@example.com", otherOrganization);
        User otherAnalyst = createUser(RoleName.SECURITY_ANALYST,
                "other-scan-resource-analyst@example.com", otherOrganization);
        User superAdmin = createUser(RoleName.SUPER_ADMIN, "scan-resource-super-admin@example.com", null);
        Target target = createTarget(organization, admin, TargetStatus.APPROVED);
        assignTarget(target, analyst, admin);
        long completedScanId = createScan(login(analyst.getEmail()), target.getId());
        ScanJob completedScan = scanJobRepository.findById(completedScanId).orElseThrow();
        completedScan.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        completedScan.transitionTo(ScanStatus.RUNNING, 10, "Running", null);
        completedScan.transitionTo(ScanStatus.COMPLETED, 100, "Completed", null);
        scanJobRepository.saveAndFlush(completedScan);
        String foreignEvidence = "FOREIGN_ORGANIZATION_SCAN_EVIDENCE";
        scanFindingRepository.saveAndFlush(new ScanFinding(completedScan, "FOREIGN_FINDING", "HIGH",
                "FOREIGN_ORGANIZATION_COMPONENT", foreignEvidence, "Sensitive rationale", "Sensitive remediation",
                "TEST", "OBSERVED"));
        scanCrawlPageRepository.saveAndFlush(new ScanCrawlPage(
                completedScan, "https://foreign.example/private-page", 0, 200, 128, 0));

        long pendingScanId = createScan(login(analyst.getEmail()), target.getId());
        String otherAnalystToken = login(otherAnalyst.getEmail());
        String otherAdminToken = login(otherAdmin.getEmail());
        String superAdminToken = login(superAdmin.getEmail());

        mockMvc.perform(get("/api/scans/{scanId}", completedScanId)
                        .header("Authorization", "Bearer " + otherAnalystToken))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(foreignEvidence))));
        mockMvc.perform(get("/api/scans/{scanId}", completedScanId)
                        .header("Authorization", "Bearer " + superAdminToken))
                .andExpect(status().isForbidden())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(foreignEvidence))));
        mockMvc.perform(get("/api/scans/{scanId}/findings", completedScanId)
                        .header("Authorization", "Bearer " + otherAnalystToken))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(foreignEvidence))));
        mockMvc.perform(get("/api/scans/{scanId}/report", completedScanId)
                        .header("Authorization", "Bearer " + otherAnalystToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/{scanId}/analytics", completedScanId)
                        .header("Authorization", "Bearer " + otherAnalystToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/{scanId}/report/export", completedScanId)
                        .param("format", "pdf")
                        .header("Authorization", "Bearer " + otherAnalystToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/{scanId}/crawl-pages", completedScanId)
                        .header("Authorization", "Bearer " + otherAnalystToken))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("foreign.example"))));
        mockMvc.perform(post("/api/scans/{scanId}/cancel", completedScanId)
                        .header("Authorization", "Bearer " + otherAnalystToken))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(foreignEvidence))));
        mockMvc.perform(post("/api/scans/{scanId}/approve", pendingScanId)
                        .header("Authorization", "Bearer " + otherAdminToken))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(foreignEvidence))));
        mockMvc.perform(post("/api/scans/{scanId}/reject", pendingScanId)
                        .header("Authorization", "Bearer " + otherAdminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reason\":\"Unauthorized cross-tenant attempt\"}"))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(foreignEvidence))));

        assertEquals(ScanStatus.COMPLETED,
                scanJobRepository.findById(completedScanId).orElseThrow().getStatus());
        assertEquals(ScanStatus.PENDING_APPROVAL,
                scanJobRepository.findById(pendingScanId).orElseThrow().getStatus());
    }

    @Test
    void targetAssignmentControlsScanCreationHistoryResourcesAndRevocation() throws Exception {
        Organization organization = approvedOrganization("Assigned Scan Tenant");
        User admin = createUser(RoleName.ADMIN, "assigned-scan-admin@example.com", organization);
        User firstAnalyst = createUser(RoleName.SECURITY_ANALYST, "first-assigned@example.com", organization);
        User secondAnalyst = createUser(RoleName.SECURITY_ANALYST, "second-assigned@example.com", organization);
        Target target = createTarget(organization, admin, TargetStatus.APPROVED);
        String adminToken = login(admin.getEmail());
        String firstToken = login(firstAnalyst.getEmail());
        String secondToken = login(secondAnalyst.getEmail());

        mockMvc.perform(post("/api/scans")
                        .header("Authorization", "Bearer " + firstToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(scanRequest(target.getId())))
                .andExpect(status().isNotFound());

        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", target.getId(), firstAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
        long scanId = createScan(firstToken, target.getId());
        ScanJob scan = scanJobRepository.findById(scanId).orElseThrow();
        scan.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        scan.transitionTo(ScanStatus.RUNNING, 10, "Running", null);
        scan.transitionTo(ScanStatus.COMPLETED, 100, "Completed", null);
        scanJobRepository.saveAndFlush(scan);
        scanFindingRepository.saveAndFlush(new ScanFinding(scan, "ASSIGNED_FINDING", "HIGH",
                "component", "finding evidence", "reason", "fix", "TEST", "OBSERVED"));
        scanCrawlPageRepository.saveAndFlush(
                new ScanCrawlPage(scan, "https://example.org/assigned", 0, 200, 64, 0));

        mockMvc.perform(get("/api/scans").header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content.length()").value(0));
        mockMvc.perform(get("/api/scans/me/dashboard").header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.approvedTargets").value(0));
        mockMvc.perform(get("/api/scans/{scanId}", scanId).header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/{scanId}/findings", scanId)
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/{scanId}/crawl-pages", scanId)
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/{scanId}/report", scanId)
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/{scanId}/report/export", scanId)
                        .param("format", "json")
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isNotFound());

        mockMvc.perform(put("/api/targets/{targetId}/assignments/{analystId}", target.getId(),
                        secondAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/targets/{targetId}", target.getId())
                        .header("Authorization", "Bearer " + firstToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/{scanId}", scanId)
                        .header("Authorization", "Bearer " + firstToken))
                .andExpect(status().isNotFound());
        for (String endpoint : List.of("/findings", "/crawl-pages", "/report", "/report/export", "/analytics")) {
            var request = get("/api/scans/{scanId}" + endpoint, scanId)
                    .header("Authorization", "Bearer " + firstToken);
            if (endpoint.equals("/report/export")) {
                request = request.param("format", "json");
            }
            mockMvc.perform(request).andExpect(status().isNotFound());
        }
        mockMvc.perform(get("/api/scans/{scanId}/report", scanId)
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.findings[0].checkType").value("ASSIGNED_FINDING"));
        mockMvc.perform(get("/api/scans/{scanId}/analytics", scanId)
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalFindings").value(1));
        mockMvc.perform(get("/api/scans/{scanId}/crawl-pages", scanId)
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1));
        mockMvc.perform(get("/api/scans").header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content.length()").value(1));
        mockMvc.perform(get("/api/scans/me/dashboard").header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.approvedTargets").value(1))
                .andExpect(jsonPath("$.data.completedScans").value(1))
                .andExpect(jsonPath("$.data.highSeverityFindings").value(1));

        mockMvc.perform(delete("/api/targets/{targetId}/assignments/{analystId}", target.getId(),
                        secondAnalyst.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
        for (String endpoint : List.of("", "/findings", "/crawl-pages", "/report", "/report/export", "/analytics")) {
            var request = get("/api/scans/{scanId}" + endpoint, scanId)
                    .header("Authorization", "Bearer " + secondToken);
            if (endpoint.equals("/report/export")) {
                request = request.param("format", "json");
            }
            mockMvc.perform(request).andExpect(status().isNotFound());
        }
        mockMvc.perform(get("/api/scans/{scanId}", scanId).header("Authorization", "Bearer " + firstToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/scans/me/dashboard").header("Authorization", "Bearer " + firstToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.approvedTargets").value(0))
                .andExpect(jsonPath("$.data.completedScans").value(0));
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

    private void assignTarget(Target target, User analyst, User admin) {
        assignmentRepository.saveAndFlush(new TargetAnalystAssignment(target, analyst, admin));
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

    private ScanJob completeScan(long scanId) {
        ScanJob scan = scanJobRepository.findById(scanId).orElseThrow();
        scan.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        scan.transitionTo(ScanStatus.RUNNING, 10, "Running", null);
        scan.transitionTo(ScanStatus.COMPLETED, 100, "Completed", null);
        return scanJobRepository.saveAndFlush(scan);
    }

    private ScanJob completedAnalyticsScan(Target target, User analyst, User reviewer, ScanType scanType) {
        ScanJob scan = new ScanJob(target, target.getOrganization(), analyst, scanType);
        scan.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Pending approval", null);
        scan.approve(reviewer);
        scan.transitionTo(ScanStatus.RUNNING, 10, "Running", null);
        scan.updateNativeEngineStatus("COMPLETED");
        scan.updateZapEngineStatus("COMPLETED");
        scan.updateZapPassiveStatus("COMPLETED");
        scan.transitionTo(ScanStatus.COMPLETED, 100, "Completed", null);
        return scanJobRepository.saveAndFlush(scan);
    }

    private String scanRequest(Long targetId) throws Exception {
        return objectMapper.writeValueAsString(java.util.Map.of("targetId", targetId, "scanType", "PASSIVE_HEADERS"));
    }

    private String login(String email) throws Exception {
        return LoginOtpTestSupport.completeLogin(
                mockMvc, objectMapper, passwordResetEmailService, email, PASSWORD);
    }
}
