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
import java.util.List;
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
        job.updateZapEngineStatus("UNAVAILABLE");
        job.updateZapFailureReason("ZAP_HEALTH_CHECK_FAILED");
        job.recordNvdLookupStatus(NvdLookupStatus.RATE_LIMITED);
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
                .andExpect(jsonPath("$.data.executionSummary.zapRequested").value(true))
                .andExpect(jsonPath("$.data.executionSummary.zapEngineStatus").value("UNAVAILABLE"))
                .andExpect(jsonPath("$.data.executionSummary.zapFailureReason").value("ZAP_HEALTH_CHECK_FAILED"))
                .andExpect(jsonPath("$.data.executionSummary.zapSpiderStatus").value("NOT_STARTED"))
                .andExpect(jsonPath("$.data.executionSummary.zapPassiveStatus").value("NOT_STARTED"))
                .andExpect(jsonPath("$.data.executionSummary.nvdLookupStatus").value("RATE_LIMITED"))
                .andExpect(jsonPath("$.data.executionSummary.discoveredPageCount").value(3))
                .andExpect(jsonPath("$.data.executionSummary.visitedPageCount").value(2))
                .andExpect(jsonPath("$.data.executionSummary.testedPassivePageCount").value(2))
                .andExpect(jsonPath("$.data.executionSummary.checksInScope").value(
                        org.hamcrest.Matchers.hasItem("OWASP ZAP spider and passive analysis")))
                .andExpect(jsonPath("$.data.severitySummary.high").value(1))
                .andExpect(jsonPath("$.data.severitySummary.medium").value(1))
                .andExpect(jsonPath("$.data.severitySummary.low").value(1))
                .andExpect(jsonPath("$.data.severitySummary.total").value(3))
                .andReturn();

        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        assertEquals(3, json.path("data").path("findings").size());
    }

    @Test
    void reportContainsOnlyFindingsFromTheRequestedScan() throws Exception {
        Organization organization = approvedOrganization("Isolated Findings Tenant");
        User analyst = createUser(RoleName.SECURITY_ANALYST, "isolated-findings@example.com", organization);
        Target target = createTarget(organization, analyst, TargetStatus.APPROVED);
        ScanJob firstScan = completedScan(target, organization, analyst);
        ScanJob secondScan = completedScan(target, organization, analyst);
        scanFindingRepository.save(new ScanFinding(firstScan, "FIRST_SCAN_FINDING", "HIGH",
                "first-endpoint", "first evidence", "first rationale", "first remediation",
                "TEST", "OBSERVED"));
        scanFindingRepository.save(new ScanFinding(secondScan, "SECOND_SCAN_FINDING", "LOW",
                "second-endpoint", "second evidence", "second rationale", "second remediation",
                "TEST", "OBSERVED"));
        scanFindingRepository.flush();
        String token = login(analyst.getEmail());

        mockMvc.perform(get("/api/scans/{scanId}/report", firstScan.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.totalFindings").value(1))
                .andExpect(jsonPath("$.data.severitySummary.high").value(1))
                .andExpect(jsonPath("$.data.findings[0].checkType").value("FIRST_SCAN_FINDING"));
        mockMvc.perform(get("/api/scans/{scanId}/report/export", secondScan.getId())
                        .param("format", "json")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("SECOND_SCAN_FINDING")))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("FIRST_SCAN_FINDING"))));
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
        job.updateZapEngineStatus("UNAVAILABLE");
        job.updateZapFailureReason("ZAP_HEALTH_CHECK_FAILED");
        job.recordNvdLookupStatus(NvdLookupStatus.RATE_LIMITED);
        job.updateCrawlCounts(4, 3, 3);
        scanJobRepository.saveAndFlush(job);

        scanFindingRepository.save(new ScanFinding(job, "MISSING_CONTENT_SECURITY_POLICY", "MEDIUM",
                "Content-Security-Policy", "Header absent with token Bearer secret-123456", "Rationale", "Add CSP",
                "PASSIVE_HEADERS", "VERIFIED"));

        scanFindingRepository.save(new ScanFinding(job, "FORMULA_FIXTURE", "LOW",
                "=HYPERLINK(\"https://attacker.invalid\")",
                "a".repeat(85) + "😀; café 東京 😀 (sample) \\ path\nnext", "Test fixture", "Review",
                "TEST", "OBSERVED"));
        for (int index = 0; index < 30; index++) {
            String component = switch (index) {
                case 0 -> "+1";
                case 1 -> "-1";
                case 2 -> "@SUM";
                case 3 -> "  =1";
                default -> "component-" + index;
            };
            scanFindingRepository.save(new ScanFinding(job, "TEST_FINDING_" + index, "LOW",
                    component, "controlled fixture", "Test fixture", "Review",
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
        JsonNode jsonReport = objectMapper.readTree(jsonBody);
        assertEquals(job.getId(), jsonReport.path("scanId").asLong());
        assertEquals(32, jsonReport.path("totalFindings").asInt());
        assertEquals("UNAVAILABLE",
                jsonReport.path("executionSummary").path("zapEngineStatus").asText());
        assertTrue(jsonBody.contains("MISSING_CONTENT_SECURITY_POLICY"));
        assertTrue(jsonBody.contains("\"nativeEngineStatus\" : \"COMPLETED\""));
        assertTrue(jsonBody.contains("\"zapRequested\" : true"));
        assertTrue(jsonBody.contains("\"zapEngineStatus\" : \"UNAVAILABLE\""));
        assertTrue(jsonBody.contains("\"zapFailureReason\" : \"ZAP_HEALTH_CHECK_FAILED\""));
        assertTrue(jsonBody.contains("\"zapSpiderStatus\" : \"NOT_STARTED\""));
        assertTrue(jsonBody.contains("\"zapPassiveStatus\" : \"NOT_STARTED\""));
        assertTrue(jsonBody.contains("\"nvdLookupStatus\" : \"RATE_LIMITED\""));
        assertTrue(jsonBody.contains("\"discoveredPageCount\" : 4"));
        assertTrue(jsonBody.contains("\"totalFindings\" : 32"));
        assertTrue(jsonBody.contains("\"medium\" : 1"));
        assertTrue(jsonBody.contains("\"low\" : 31"));
        assertTrue(jsonBody.contains("\"detectionSource\" : \"PASSIVE_HEADERS\""));
        assertTrue(jsonBody.contains("東京"));
        assertTrue(jsonBody.contains("😀") || jsonBody.contains("\\uD83D\\uDE00"));
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
        List<List<String>> csvRows = parseCsvRows(csvBody);
        List<String> csvHeader = csvRows.stream()
                .filter(row -> !row.isEmpty() && "Finding ID".equals(row.getFirst()))
                .findFirst().orElseThrow();
        List<String> formulaRow = csvRows.stream()
                .filter(row -> row.size() > 1 && "FORMULA_FIXTURE".equals(row.get(1)))
                .findFirst().orElseThrow();
        assertEquals(15, csvHeader.size());
        assertEquals(15, formulaRow.size());
        assertEquals("'=HYPERLINK(\"https://attacker.invalid\")", formulaRow.get(3));
        assertTrue(formulaRow.get(4).contains("café 東京 😀"));
        assertTrue(formulaRow.get(4).contains("next"));
        assertFalse(formulaRow.get(4).contains("\n"));
        assertTrue(csvBody.startsWith("# Scan ID,"));
        assertTrue(csvBody.contains("Finding ID,Check Type,Severity"));
        assertTrue(csvBody.contains("MISSING_CONTENT_SECURITY_POLICY"));
        assertTrue(csvBody.contains("# OWASP ZAP Status,UNAVAILABLE"));
        assertTrue(csvBody.contains("# OWASP ZAP Requested,true"));
        assertTrue(csvBody.contains("# OWASP ZAP Failure Reason,ZAP_HEALTH_CHECK_FAILED"));
        assertTrue(csvBody.contains("# ZAP Spider Status,NOT_STARTED"));
        assertTrue(csvBody.contains("# ZAP Passive Analysis Status,NOT_STARTED"));
        assertTrue(csvBody.contains("# NVD Lookup Status,RATE_LIMITED"));
        assertTrue(csvBody.contains("# Discovered Same-Origin Pages,4"));
        assertTrue(csvBody.contains("# Passively Tested Pages,3"));
        assertTrue(csvBody.contains("# Persisted HTML Crawl Records,0"));
        assertTrue(csvBody.contains("# High,0,Medium,1,Low,31,Total,32"));
        assertTrue(csvBody.contains("PASSIVE_HEADERS"));
        assertTrue(csvBody.contains("'=HYPERLINK("));
        assertTrue(csvBody.contains("東京"));
        assertTrue(csvBody.contains("😀"));
        assertTrue(csvBody.contains("LOW,'+1,"));
        assertTrue(csvBody.contains("LOW,'-1,"));
        assertTrue(csvBody.contains("LOW,'@SUM,"));
        assertTrue(csvBody.contains("LOW,'  =1,"));
        assertTrue(csvBody.contains("LOW,component-4,"));
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
        assertPdfStructure(pdfBytes);
        assertTrue(pdfBytes.length > 100);
        String pdfHeader = new String(pdfBytes, 0, 8, StandardCharsets.ISO_8859_1);
        assertTrue(pdfHeader.startsWith("%PDF-1.4"));
        String pdfTail = new String(pdfBytes, pdfBytes.length - 10, 10, StandardCharsets.ISO_8859_1);
        assertTrue(pdfTail.contains("%%EOF"));
        String pdfBody = new String(pdfBytes, StandardCharsets.ISO_8859_1);
        assertTrue(pdfBody.contains("OWASP ZAP: UNAVAILABLE"));
        assertTrue(pdfBody.contains("OWASP ZAP requested: true"));
        assertTrue(pdfBody.contains("ZAP_HEALTH_CHECK_FAILED"));
        assertTrue(pdfBody.contains("ZAP spider: NOT_STARTED"));
        assertTrue(pdfBody.contains("ZAP passive analysis: NOT_STARTED"));
        assertTrue(pdfBody.contains("ZAP active scan: NOT_EXECUTED"));
        assertTrue(pdfBody.contains("NVD lookup: RATE_LIMITED"));
        assertTrue(pdfBody.contains("Severity totals: High 0, Medium 1, Low 31, Total 32"));
        assertTrue(pdfBody.contains("Evidence:"));
        assertTrue(pdfBody.contains("Header absent"));
        assertTrue(pdfBody.contains("café"));
        assertTrue(pdfBody.contains("\\u{6771}"));
    }

    @Test
    void completedScanWithNoFindingsExportsAnEmptyButStructuredReport() throws Exception {
        Organization organization = approvedOrganization("Empty Report Tenant");
        User analyst = createUser(RoleName.SECURITY_ANALYST, "empty-report@example.com", organization);
        Target target = createTarget(organization, analyst, TargetStatus.APPROVED);
        ScanJob job = completedScan(target, organization, analyst);
        String token = login(analyst.getEmail());

        MvcResult jsonResult = mockMvc.perform(get("/api/scans/{scanId}/report/export", job.getId())
                        .param("format", "json")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode jsonReport = objectMapper.readTree(jsonResult.getResponse().getContentAsString());
        assertEquals(0, jsonReport.path("totalFindings").asInt());
        assertTrue(jsonReport.path("findings").isArray());
        assertTrue(jsonReport.path("findings").isEmpty());

        MvcResult csvResult = mockMvc.perform(get("/api/scans/{scanId}/report/export", job.getId())
                        .param("format", "csv")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        List<List<String>> csvRows = parseCsvRows(csvResult.getResponse().getContentAsString());
        assertTrue(csvRows.stream().anyMatch(row -> !row.isEmpty() && "Finding ID".equals(row.getFirst())));
        assertFalse(csvRows.stream().anyMatch(row -> row.size() > 1 && row.get(1).startsWith("MISSING_")));

        MvcResult pdfResult = mockMvc.perform(get("/api/scans/{scanId}/report/export", job.getId())
                        .param("format", "pdf")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        assertPdfStructure(pdfResult.getResponse().getContentAsByteArray());
        assertTrue(new String(pdfResult.getResponse().getContentAsByteArray(), StandardCharsets.ISO_8859_1)
                .contains("No findings were persisted for this scan."));
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
        String foreignEvidence = "FOREIGN_ORGANIZATION_REPORT_EVIDENCE";
        scanFindingRepository.saveAndFlush(new ScanFinding(jobA, "FOREIGN_REPORT_FINDING", "HIGH",
                "foreign-component", foreignEvidence, "Sensitive rationale", "Sensitive remediation",
                "TEST", "OBSERVED"));

        String tokenB = login(analystB.getEmail());

        mockMvc.perform(get("/api/scans/{scanId}/report", jobA.getId())
                        .header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isNotFound())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(foreignEvidence))));
        for (String format : new String[]{"json", "csv", "pdf"}) {
            mockMvc.perform(get("/api/scans/{scanId}/report/export", jobA.getId())
                            .param("format", format)
                            .header("Authorization", "Bearer " + tokenB))
                    .andExpect(status().isNotFound())
                    .andExpect(content().string(org.hamcrest.Matchers.not(
                            org.hamcrest.Matchers.containsString(foreignEvidence))));
        }
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

    private List<List<String>> parseCsvRows(String csv) {
        List<List<String>> rows = new java.util.ArrayList<>();
        List<String> row = new java.util.ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for (int index = 0; index < csv.length(); index++) {
            char current = csv.charAt(index);
            if (quoted) {
                if (current == '"' && index + 1 < csv.length() && csv.charAt(index + 1) == '"') {
                    field.append('"');
                    index++;
                } else if (current == '"') {
                    quoted = false;
                } else {
                    field.append(current);
                }
            } else if (current == '"' && field.isEmpty()) {
                quoted = true;
            } else if (current == ',') {
                row.add(field.toString());
                field.setLength(0);
            } else if (current == '\n') {
                row.add(field.toString());
                field.setLength(0);
                rows.add(List.copyOf(row));
                row.clear();
            } else if (current != '\r') {
                field.append(current);
            }
        }
        if (quoted) {
            throw new AssertionError("CSV export contains an unterminated quoted field");
        }
        if (!row.isEmpty() || !field.isEmpty()) {
            row.add(field.toString());
            rows.add(List.copyOf(row));
        }
        return List.copyOf(rows);
    }

    private void assertPdfStructure(byte[] pdfBytes) {
        String pdf = new String(pdfBytes, StandardCharsets.ISO_8859_1);
        String marker = "startxref\n";
        int markerIndex = pdf.lastIndexOf(marker);
        assertTrue(markerIndex >= 0);
        int offsetStart = markerIndex + marker.length();
        int offsetEnd = pdf.indexOf('\n', offsetStart);
        int xrefOffset = Integer.parseInt(pdf.substring(offsetStart, offsetEnd));
        assertTrue(pdf.startsWith("xref\n", xrefOffset));

        String[] xrefLines = pdf.substring(xrefOffset).split("\n");
        String[] xrefHeader = xrefLines[1].split(" ");
        int objectCount = Integer.parseInt(xrefHeader[1]);
        for (int objectId = 1; objectId < objectCount; objectId++) {
            String[] entry = xrefLines[objectId + 2].trim().split("\\s+");
            int objectOffset = Integer.parseInt(entry[0]);
            assertTrue(pdf.startsWith(objectId + " 0 obj\n", objectOffset));
        }
        assertTrue(pdf.endsWith("%%EOF\n"));
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

    private ScanJob completedScan(Target target, Organization organization, User analyst) {
        ScanJob job = new ScanJob(target, organization, analyst, ScanType.PASSIVE_HEADERS);
        job.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Pending", null);
        job.transitionTo(ScanStatus.QUEUED, 0, "Queued", null);
        job.transitionTo(ScanStatus.RUNNING, 20, "Running", null);
        job.transitionTo(ScanStatus.COMPLETED, 100, "Done", null);
        job.updateNativeEngineStatus("COMPLETED");
        return scanJobRepository.saveAndFlush(job);
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
