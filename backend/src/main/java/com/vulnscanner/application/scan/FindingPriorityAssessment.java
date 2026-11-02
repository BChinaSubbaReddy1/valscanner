package com.vulnscanner.application.scan;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public record FindingPriorityAssessment(int score, String level, String explanation) {
    public static FindingPriorityAssessment assess(String severity, String verificationStatus,
                                                   String sourceConfidence) {
        int score = severityPoints(severity);
        List<String> factors = new ArrayList<>();
        factors.add("severity " + valueOrUnknown(severity) + " +" + score);

        int verificationPoints = verificationPoints(verificationStatus);
        score += verificationPoints;
        factors.add("verification " + valueOrUnknown(verificationStatus) + " +" + verificationPoints);

        int confidencePoints = confidencePoints(sourceConfidence);
        score += confidencePoints;
        factors.add("source confidence " + valueOrUnknown(sourceConfidence) + " +" + confidencePoints);

        String level = score >= 60 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW";
        String explanation = "Technical triage heuristic (" + String.join("; ", factors)
                + "; capped at 100). Business impact, authentication context, and target exposure "
                + "are not inferred or scored when unavailable. This is not CVSS or a verified exploitability rating.";
        return new FindingPriorityAssessment(Math.min(score, 100), level, explanation);
    }

    private static int severityPoints(String severity) {
        return switch (normalize(severity)) {
            case "HIGH" -> 60;
            case "MEDIUM" -> 35;
            case "LOW" -> 10;
            default -> 0;
        };
    }

    private static int verificationPoints(String verificationStatus) {
        return switch (normalize(verificationStatus)) {
            case "CONFIRMED" -> 15;
            case "SUSPECTED" -> 8;
            case "POTENTIAL" -> 3;
            default -> 0;
        };
    }

    private static int confidencePoints(String confidence) {
        return switch (normalize(confidence)) {
            case "HIGH" -> 10;
            case "MEDIUM" -> 5;
            default -> 0;
        };
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private static String valueOrUnknown(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value.trim().toUpperCase(Locale.ROOT);
    }
}
