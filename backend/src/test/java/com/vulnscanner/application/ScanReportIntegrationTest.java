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
import com.vulnscanner.application.target.Target;
import com.vulnscanner.application.target.TargetRepository;
import com.vulnscanner.application.target.TargetStatus;
import com.vulnscanner.application.target.TargetType;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class ScanReportIntegrationTest {
    private static final String PASSWORD = "SecurePassword123!";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private OrganizationRepository organizationRepository;
    @Autowired private TargetRepository targetRepository;
    @Autowired private ScanJobRepository scanJobRepository;
    @Autowired private ScanFindingRepository scanFindingRepository;
    @Autowired private ScanCrawlPageRepository scanCrawlPageRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    @BeforeEach
    void initializeRoles() {
        for (RoleName name : new RoleName[]{RoleName.SUPER_ADMIN, RoleName.ADMIN, RoleName.SECURITY_ANALYST}) {
            roleRepository.findByName(name).orElseGet(() -> roleRepository.save(new Role(name)));
        }
    }

    @Test
    void generatesAccurateReportWithSeverityTotalsAndTargetDetails() throws Exception {
        Organization organization = approvedOrganization("Report Tenant");
        User analyst = createUser(RoleName.SECURITY_ANALYST, "report-analyst@example.com", organization);
        Target target = createTarget(organization, analyst, TargetStatus.APPROVED);

        ScanJob job = scanJobRepository.save(new ScanJob(target, organization, analyst, ScanType.PASSIVE_HEADERS));
        job.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Pending", null);
        job.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        job.transitionTo(ScanStatus.RUNNING, 20, "Running", null);
        job.transitionTo(ScanStatus.COMPLETED, 100, "Done", null);
        job.updateNativeEngineStatus("COMPLETED");
        job.updateCrawlCounts(3, 2, 2);
        scanJobRepository.saveAndFlush(job);

        scanFindingRepository.save(new ScanFinding(job, "SQL_INJECTION_SUSPECTED", "HIGH",
                "https://example.org/?id=1", "error syntax near token", "Rationale", "Use parameterized queries",
                "ACTIVE_QUERY_PARAMETER", "SUSPECTED"));
        scanFindingRepository.save(new ScanFinding(job, "MISSING_CONTENT_SECURITY_POLICY", "MEDIUM",
                "Content-Security-Policy", "Header absent", "Rationale", "Add CSP",
                "PASSIVE_HEADERS", "VERIFIED"));
        scanFindingRepository.save(new ScanFinding(job, "MISSING_REFERRER_POLICY", "LOW",
                "Referrer-Policy", "Header absent", "Rationale", "Add Referrer-Policy",
                "PASSIVE_HEADERS", "VERIFIED"));
        scanCrawlPageRepository.save(new ScanCrawlPage(job, "https://example.org/", 0, 200, 500, 2));

        String token = login(analyst.getEmail());

        MvcResult result = mockMvc.perform(get("/api/scans/{scanId}/report", job.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.scanId").value(job.getId()))
                .andExpect(jsonPath("$.data.targetName").value(target.getName()))
                .andExpect(jsonPath("$.data.targetUrl").value(target.getUrl()))
                .andExpect(jsonPath("$.data.status").value("COMPLETED"))
                .andExpect(jsonPath("$.data.totalFindings").value(3))
                .andExpect(jsonPath("$.data.totalCrawlPages").value(1))
                .andExpect(jsonPath("$.data.executionSummary.nativeEngineStatus").value("COMPLETED"))
                .andExpect(jsonPath("$.data.executionSummary.zapEngineStatus").value("NOT_REQUESTED"))
                .andExpect(jsonPath("$.data.executionSummary.discoveredPageCount").value(3))
                .andExpect(jsonPath("$.data.executionSummary.visitedPageCount").value(2))
                .andExpect(jsonPath("$.data.executionSummary.testedPassivePageCount").value(2))
                .andExpect(jsonPath("$.data.executionSummary.checksOutOfScope").value(
                        org.hamcrest.Matchers.hasItem("OWASP ZAP spider or passive analysis")))
                .andExpect(jsonPath("$.data.severitySummary.high").value(1))
                .andExpect(jsonPath("$.data.severitySummary.medium").value(1))
                .andExpect(jsonPath("$.data.severitySummary.low").value(1))
                .andExpect(jsonPath("$.data.severitySummary.total").value(3))
                .andReturn();

        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(3, json.path("data").path("findings").size());
    }

    @Test
    void exportsPdfCsvAndJsonCorrectly() throws Exception {
        Organization organization = approvedOrganization("Export Tenant");
        User analyst = createUser(RoleName.SECURITY_ANALYST, "export-analyst@example.com", organization);
        Target target = createTarget(organization, analyst, TargetStatus.APPROVED);

        ScanJob job = scanJobRepository.save(new ScanJob(target, organization, analyst, ScanType.PASSIVE_HEADERS));
        job.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Pending", null);
        job.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        job.transitionTo(ScanStatus.RUNNING, 20, "Running", null);
        job.transitionTo(ScanStatus.COMPLETED, 100, "Done", null);
        job.updateNativeEngineStatus("COMPLETED");
        job.updateCrawlCounts(4, 3, 3);
        scanJobRepository.saveAndFlush(job);

        scanFindingRepository.save(new ScanFinding(job, "MISSING_CONTENT_SECURITY_POLICY", "MEDIUM",
                "Content-Security-Policy", "Header absent with token Bearer secret-123456", "Rationale", "Add CSP",
                "PASSIVE_HEADERS", "VERIFIED"));

        scanFindingRepository.save(new ScanFinding(job, "FORMULA_FIXTURE", "LOW",
                "=HYPERLINK(\"https://attacker.invalid\")", "controlled fixture", "Test fixture", "Review",
                "TEST", "OBSERVED"));
        for (int index = 0; index < 30; index++) {
            scanFindingRepository.save(new ScanFinding(job, "TEST_FINDING_" + index, "LOW",
                    "component-" + index, "controlled fixture", "Test fixture", "Review",
                    "TEST", "OBSERVED"));
        }

        String token = login(analyst.getEmail());

        // JSON export
        MvcResult jsonResult = mockMvc.perform(get("/api/scans/{scanId}/report/export", job.getId())
                        .param("format", "json")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json; charset=UTF-8"))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"scan-report-" + job.getId() + ".json\""))
                .andReturn();
        String jsonBody = jsonResult.getResponse().getContentAsString();
        assertTrue(jsonBody.contains("MISSING_CONTENT_SECURITY_POLICY"));
        assertTrue(jsonBody.contains("\"nativeEngineStatus\" : \"COMPLETED\""));
        assertTrue(jsonBody.contains("\"zapEngineStatus\" : \"NOT_REQUESTED\""));
        assertTrue(jsonBody.contains("\"discoveredPageCount\" : 4"));
        assertTrue(jsonBody.contains("\"totalFindings\" : 32"));
        assertTrue(jsonBody.contains("\"medium\" : 1"));
        assertTrue(jsonBody.contains("\"low\" : 31"));
        assertTrue(jsonBody.contains("\"detectionSource\" : \"PASSIVE_HEADERS\""));
        // Check redaction
        assertFalse(jsonBody.contains("secret-123456"));
        assertTrue(jsonBody.contains("[REDACTED]"));

        // CSV export
        MvcResult csvResult = mockMvc.perform(get("/api/scans/{scanId}/report/export", job.getId())
                        .param("format", "csv")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "text/csv; charset=UTF-8"))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"scan-report-" + job.getId() + ".csv\""))
                .andReturn();
        String csvBody = csvResult.getResponse().getContentAsString();
        assertTrue(csvBody.startsWith("# Scan ID,"));
        assertTrue(csvBody.contains("Finding ID,Check Type,Severity"));
        assertTrue(csvBody.contains("MISSING_CONTENT_SECURITY_POLICY"));
        assertTrue(csvBody.contains("# OWASP ZAP Status,NOT_REQUESTED"));
        assertTrue(csvBody.contains("# Discovered Same-Origin Pages,4"));
        assertTrue(csvBody.contains("# Passively Tested Pages,3"));
        assertTrue(csvBody.contains("# Persisted HTML Crawl Records,0"));
        assertTrue(csvBody.contains("# High,0,Medium,1,Low,31,Total,32"));
        assertTrue(csvBody.contains("PASSIVE_HEADERS"));
        assertTrue(csvBody.contains("'=HYPERLINK("));
        assertFalse(csvBody.contains("secret-123456"));

        // PDF export
        MvcResult pdfResult = mockMvc.perform(get("/api/scans/{scanId}/report/export", job.getId())
                        .param("format", "pdf")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/pdf"))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"scan-report-" + job.getId() + ".pdf\""))
                .andReturn();
        byte[] pdfBytes = pdfResult.getResponse().getContentAsByteArray();
        assertTrue(pdfBytes.length > 100);
        String pdfHeader = new String(pdfBytes, 0, 8, StandardCharsets.ISO_8859_1);
        assertTrue(pdfHeader.startsWith("%PDF-1.4"));
        String pdfTail = new String(pdfBytes, pdfBytes.length - 10, 10, StandardCharsets.ISO_8859_1);
        assertTrue(pdfTail.contains("%%EOF"));
        String pdfBody = new String(pdfBytes, StandardCharsets.ISO_8859_1);
        assertTrue(pdfBody.contains("OWASP ZAP: NOT_REQUESTED"));
        assertTrue(pdfBody.contains("Severity totals: High 0, Medium 1, Low 31, Total 32"));
        assertTrue(pdfBody.contains("Evidence:"));
        assertTrue(pdfBody.contains("Header absent"));
        assertTrue(pdfBody.contains("Detection source: PASSIVE_HEADERS | Assessment status: VERIFIED"));
        assertTrue(pdfBody.contains("Assessment note: Automated status does not independently confirm exploitability."));
        assertTrue(pdfBody.contains("TEST_FINDING_29"));
        assertFalse(pdfBody.contains("PDF summary limit:"));
    }

    @Test
    void handlesFailedAndCancelledScansGracefully() throws Exception {
        Organization organization = approvedOrganization("Failed Scan Tenant");
        User analyst = createUser(RoleName.SECURITY_ANALYST, "failed-analyst@example.com", organization);
        Target target = createTarget(organization, analyst, TargetStatus.APPROVED);

        ScanJob failedJob = scanJobRepository.save(new ScanJob(target, organization, analyst, ScanType.PASSIVE_HEADERS));
        failedJob.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Pending", null);
        failedJob.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        failedJob.transitionTo(ScanStatus.FAILED, 10, "Target request timed out", ScanFailureReason.TIME_BUDGET_EXCEEDED);
        scanJobRepository.saveAndFlush(failedJob);

        String token = login(analyst.getEmail());

        mockMvc.perform(get("/api/scans/{scanId}/report", failedJob.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("FAILED"))
                .andExpect(jsonPath("$.data.progress").value(10))
                .andExpect(jsonPath("$.data.failureReason").value("TIME_BUDGET_EXCEEDED"))
                .andExpect(jsonPath("$.data.totalFindings").value(0));
    }

    @Test
    void enforcesTenantIsolationOnReports() throws Exception {
        Organization organizationA = approvedOrganization("Tenant Alpha");
        Organization organizationB = approvedOrganization("Tenant Beta");
        User analystA = createUser(RoleName.SECURITY_ANALYST, "alpha-analyst@example.com", organizationA);
        User analystB = createUser(RoleName.SECURITY_ANALYST, "beta-analyst@example.com", organizationB);
        Target targetA = createTarget(organizationA, analystA, TargetStatus.APPROVED);

        ScanJob jobA = scanJobRepository.save(new ScanJob(targetA, organizationA, analystA, ScanType.PASSIVE_HEADERS));
        jobA.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Pending", null);
        jobA.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        jobA.transitionTo(ScanStatus.RUNNING, 20, "Running", null);
        jobA.transitionTo(ScanStatus.COMPLETED, 100, "Done", null);
        scanJobRepository.saveAndFlush(jobA);

        String tokenB = login(analystB.getEmail());

        // Foreign organization request must return 404
        mockMvc.perform(get("/api/scans/{scanId}/report", jobA.getId())
                        .header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/api/scans/{scanId}/report/export", jobA.getId())
                        .param("format", "pdf")
                        .header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isNotFound());
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

    private String login(String email) throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(response).path("data").path("token").asText();
    }
}
