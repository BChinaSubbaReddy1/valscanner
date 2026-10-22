package com.vulnscanner.application.scan;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class PdfReportGenerator {

    private PdfReportGenerator() {
    }

    public static byte[] generate(ScanReportResponse report) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            List<Long> offsets = new ArrayList<>();

            write(out, "%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n");

            // 1 0 obj: Catalog
            offsets.add((long) out.size());
            write(out, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

            // 2 0 obj: Pages
            offsets.add((long) out.size());
            write(out, "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

            // 3 0 obj: Page
            offsets.add((long) out.size());
            write(out, "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj\n");

            // Content stream
            StringBuilder content = new StringBuilder();
            content.append("BT\n");

            int y = 740;
            // Title
            content.append("/F2 20 Tf\n");
            content.append(String.format("50 %d Td\n", y));
            content.append(String.format("(%s) Tj\n", escapePdf("Web Application Vulnerability Scan Report")));

            // Metadata
            content.append("/F1 10 Tf\n");
            y = -25;
            content.append(String.format("0 %d Td\n", y));
            content.append(String.format("(Scan ID: %s | Target: %s (%s)) Tj\n",
                    report.scanId(), escapePdf(report.targetName()), escapePdf(report.targetUrl())));

            y = -15;
            content.append(String.format("0 %d Td\n", y));
            content.append(String.format("(Status: %s | Progress: %d%% | Status Message: %s) Tj\n",
                    report.status(), report.progress(), escapePdf(report.statusMessage() != null ? report.statusMessage() : "")));

            y = -15;
            content.append(String.format("0 %d Td\n", y));
            content.append(String.format("(Created: %s | Completed: %s) Tj\n",
                    report.createdAt(), report.completedAt() != null ? report.completedAt() : "N/A"));

            // Severity Summary
            y = -25;
            content.append("/F2 12 Tf\n");
            content.append(String.format("0 %d Td\n", y));
            content.append(String.format("(Severity Summary - High: %d, Medium: %d, Low: %d, Total Findings: %d, Crawled Pages: %d) Tj\n",
                    report.severitySummary().high(), report.severitySummary().medium(),
                    report.severitySummary().low(), report.totalFindings(), report.totalCrawlPages()));

            // Findings list
            content.append("/F1 9 Tf\n");
            y = -20;
            content.append(String.format("0 %d Td\n", y));
            content.append("(Findings:) Tj\n");

            int lineBudget = 25;
            if (report.findings().isEmpty()) {
                content.append("0 -15 Td\n");
                content.append("(No vulnerabilities identified for this scan.) Tj\n");
            } else {
                int includedFindings = 0;
                for (ScanFindingResponse finding : report.findings()) {
                    if (lineBudget <= 0) {
                        break;
                    }
                    content.append("0 -15 Td\n");
                    content.append(String.format("([%s] %s - Component: %s) Tj\n",
                            escapePdf(finding.severity()), escapePdf(finding.checkType()),
                            escapePdf(truncate(finding.affectedComponent(), 60))));
                    includedFindings++;
                    lineBudget--;

                    if (lineBudget > 0 && finding.remediation() != null && !finding.remediation().isBlank()) {
                        content.append("0 -12 Td\n");
                        content.append(String.format("(   Remediation: %s) Tj\n",
                                escapePdf(truncate(finding.remediation(), 80))));
                        lineBudget--;
                    }
                }
                int omittedFindings = report.findings().size() - includedFindings;
                if (omittedFindings > 0) {
                    content.append("0 -15 Td\n");
                    content.append(String.format("(PDF summary limit: %d of %d findings shown; %d omitted.) Tj\n",
                            includedFindings, report.findings().size(), omittedFindings));
                }
            }

            content.append("ET\n");

            byte[] contentBytes = content.toString().getBytes(StandardCharsets.ISO_8859_1);

            // 4 0 obj: Content stream
            offsets.add((long) out.size());
            write(out, String.format("4 0 obj\n<< /Length %d >>\nstream\n", contentBytes.length));
            out.write(contentBytes);
            write(out, "\nendstream\nendobj\n");

            // 5 0 obj: Font regular
            offsets.add((long) out.size());
            write(out, "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");

            // 6 0 obj: Font bold
            offsets.add((long) out.size());
            write(out, "6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n");

            // Xref
            long xrefOffset = out.size();
            write(out, String.format("xref\n0 %d\n0000000000 65535 f \n", offsets.size() + 1));
            for (Long offset : offsets) {
                write(out, String.format("%010d 00000 n \n", offset));
            }

            // Trailer
            write(out, String.format("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
                    offsets.size() + 1, xrefOffset));

            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to generate PDF report", e);
        }
    }

    private static String escapePdf(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\")
                   .replace("(", "\\(")
                   .replace(")", "\\)")
                   .replace("\r", " ")
                   .replace("\n", " ");
    }

    private static String truncate(String text, int max) {
        if (text == null) return "";
        return text.length() <= max ? text : text.substring(0, max - 3) + "...";
    }

    private static void write(ByteArrayOutputStream out, String s) throws IOException {
        out.write(s.getBytes(StandardCharsets.ISO_8859_1));
    }
}
