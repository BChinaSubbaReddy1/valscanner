package com.vulnscanner.application.scan;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PdfReportGenerator {
    private static final int LINES_PER_PAGE = 54;
    private static final int WRAP_LENGTH = 96;

    private PdfReportGenerator() {
    }

    public static byte[] generate(ScanReportResponse report) {
        try {
            List<String> lines = reportLines(report);
            List<List<String>> pageLines = paginate(lines);
            int objectCount = 4 + pageLines.size() * 2;
            Map<Integer, byte[]> objects = new LinkedHashMap<>();
            objects.put(1, bytes("<< /Type /Catalog /Pages 2 0 R >>"));

            StringBuilder kids = new StringBuilder();
            for (int pageIndex = 0; pageIndex < pageLines.size(); pageIndex++) {
                kids.append(5 + pageIndex * 2).append(" 0 R ");
            }
            objects.put(2, bytes("<< /Type /Pages /Kids [" + kids + "] /Count " + pageLines.size() + " >>"));
            objects.put(3, bytes("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"));
            objects.put(4, bytes("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"));

            for (int pageIndex = 0; pageIndex < pageLines.size(); pageIndex++) {
                int pageObjectId = 5 + pageIndex * 2;
                int contentObjectId = pageObjectId + 1;
                byte[] content = pageContent(pageLines.get(pageIndex), pageIndex == 0);
                objects.put(pageObjectId, bytes("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                        + "/Contents " + contentObjectId + " 0 R "
                        + "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>"));
                objects.put(contentObjectId, streamObject(content));
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            write(out, "%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n");
            long[] offsets = new long[objectCount + 1];
            for (int objectId = 1; objectId <= objectCount; objectId++) {
                offsets[objectId] = out.size();
                write(out, objectId + " 0 obj\n");
                out.write(objects.get(objectId));
                write(out, "\nendobj\n");
            }

            long xrefOffset = out.size();
            write(out, "xref\n0 " + (objectCount + 1) + "\n0000000000 65535 f \n");
            for (int objectId = 1; objectId <= objectCount; objectId++) {
                write(out, String.format("%010d 00000 n \n", offsets[objectId]));
            }
            write(out, "trailer\n<< /Size " + (objectCount + 1)
                    + " /Root 1 0 R >>\nstartxref\n" + xrefOffset + "\n%%EOF\n");
            return out.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to generate PDF report", exception);
        }
    }

    private static List<String> reportLines(ScanReportResponse report) {
        ScanExecutionSummary scope = report.executionSummary();
        List<String> lines = new ArrayList<>();
        lines.add("Web Application Vulnerability Scan Report");
        lines.add("Scan ID: " + report.scanId());
        lines.add("Target: " + report.targetName() + " (" + report.targetUrl() + ")");
        lines.add("Scan type: " + report.scanType() + " | Status: " + report.status());
        lines.add("Native engine: " + scope.nativeEngineStatus() + " | OWASP ZAP: " + scope.zapEngineStatus());
        lines.add("Scope counts: " + count(scope.discoveredPageCount()) + " discovered, "
                + count(scope.visitedPageCount()) + " visited, " + count(scope.testedPassivePageCount())
                + " passively tested; " + report.totalCrawlPages() + " persisted HTML crawl records.");
        lines.add("Discovered is bounded same-origin link discovery; visited is successfully fetched pages; "
                + "passively tested counts pages checked by native passive response checks.");
        lines.add("Severity totals: High " + report.severitySummary().high()
                + ", Medium " + report.severitySummary().medium()
                + ", Low " + report.severitySummary().low()
                + ", Total " + report.totalFindings());
        appendWrapped(lines, "Checks in scope", String.join("; ", scope.checksInScope()));
        appendWrapped(lines, "Checks out of scope", String.join("; ", scope.checksOutOfScope()));
        appendWrapped(lines, "Status details", report.statusMessage());
        lines.add("Findings:");
        if (report.findings().isEmpty()) {
            lines.add("No findings were persisted for this scan.");
        }
        for (ScanFindingResponse finding : report.findings()) {
            lines.add("");
            lines.add("[" + finding.severity() + "] " + finding.checkType() + " (finding " + finding.id() + ")");
            appendWrapped(lines, "Affected location", finding.affectedComponent());
            appendWrapped(lines, "Evidence", finding.evidence());
            appendWrapped(lines, "Rationale", finding.rationale());
            appendWrapped(lines, "Detection source", finding.detectionSource()
                    + " | Verification: " + finding.verificationStatus());
            appendWrapped(lines, "Source metadata", "Rule " + finding.sourceRuleId()
                    + " | Confidence " + finding.sourceConfidence()
                    + " | CWE " + finding.sourceCweId()
                    + " | WASC " + finding.sourceWascId()
                    + " | Reference " + finding.sourceReference());
            appendWrapped(lines, "Remediation", finding.remediation());
        }
        return lines;
    }

    private static void appendWrapped(List<String> lines, String label, String value) {
        String text = label + ": " + (value == null || value.isBlank() ? "Not available" : value);
        for (int start = 0; start < text.length(); start += WRAP_LENGTH) {
            lines.add(text.substring(start, Math.min(text.length(), start + WRAP_LENGTH)));
        }
    }

    private static String count(Integer value) {
        return value == null ? "Not reported" : value.toString();
    }

    private static List<List<String>> paginate(List<String> lines) {
        List<List<String>> pages = new ArrayList<>();
        for (int start = 0; start < lines.size(); start += LINES_PER_PAGE) {
            pages.add(List.copyOf(lines.subList(start, Math.min(lines.size(), start + LINES_PER_PAGE))));
        }
        if (pages.isEmpty()) {
            pages.add(List.of("No report data available."));
        }
        return pages;
    }

    private static byte[] pageContent(List<String> lines, boolean firstPage) {
        StringBuilder content = new StringBuilder("BT\n/F2 14 Tf\n50 755 Td\n(")
                .append(escapePdf(firstPage ? "Scan Report" : "Scan Report (continued)"))
                .append(") Tj\n/F1 9 Tf\n0 -22 Td\n");
        for (String line : lines) {
            content.append("(").append(escapePdf(line)).append(") Tj\n0 -12 Td\n");
        }
        content.append("ET\n");
        return content.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] streamObject(byte[] content) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        write(stream, "<< /Length " + content.length + " >>\nstream\n");
        stream.write(content);
        write(stream, "\nendstream");
        return stream.toByteArray();
    }

    private static String escapePdf(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replace("\r", " ")
                .replace("\n", " ");
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static void write(ByteArrayOutputStream out, String value) throws IOException {
        out.write(value.getBytes(StandardCharsets.ISO_8859_1));
    }
}
