package com.vulnscanner.application.scan;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FindingEvaluationMetricsTest {
    @Test
    void calculatesMetricsAcrossAnExplicitFindingInstanceUniverse() {
        FindingEvaluationMetrics.Result result = FindingEvaluationMetrics.evaluate(
                Set.of("positive-1", "positive-2", "negative-1", "negative-2", "negative-3"),
                Set.of("positive-1", "positive-2"),
                Set.of("positive-1", "negative-1"));

        assertEquals(1, result.truePositive());
        assertEquals(1, result.falsePositive());
        assertEquals(1, result.falseNegative());
        assertEquals(2, result.trueNegative());
        assertEquals(OptionalDouble.of(0.5), result.precision());
        assertEquals(OptionalDouble.of(0.5), result.recall());
        assertEquals(OptionalDouble.of(0.6), result.accuracy());
        assertEquals(OptionalDouble.of(1.0 / 3.0), result.falsePositiveRate());
        assertEquals(OptionalDouble.of(0.5), result.falseNegativeRate());
        assertEquals(OptionalDouble.of(0.5), result.f1Score());
    }

    @Test
    void reportsMetricsAsUndefinedWhenTheirDenominatorsAreZero() {
        FindingEvaluationMetrics.Result result = FindingEvaluationMetrics.evaluate(
                Set.of("negative-1"), Set.of(), Set.of());

        assertEquals(OptionalDouble.empty(), result.precision());
        assertEquals(OptionalDouble.empty(), result.recall());
        assertEquals(OptionalDouble.of(1.0), result.accuracy());
        assertEquals(OptionalDouble.of(0.0), result.falsePositiveRate());
        assertEquals(OptionalDouble.empty(), result.falseNegativeRate());
        assertEquals(OptionalDouble.empty(), result.f1Score());
    }

    @Test
    void reportsAccuracyAsUndefinedForAnEmptyReferenceUniverse() {
        FindingEvaluationMetrics.Result result = FindingEvaluationMetrics.evaluate(
                Set.of(), Set.of(), Set.of());

        assertEquals(OptionalDouble.empty(), result.accuracy());
    }

    @Test
    void rejectsFindingsOutsideTheDeclaredReferenceUniverse() {
        assertThrows(IllegalArgumentException.class, () -> FindingEvaluationMetrics.evaluate(
                Set.of("case-1"), Set.of(), Set.of("unlabeled-finding")));
    }

    @Test
    void calculatesMetricsByCategoryAndEngineAndReportsExecutionCoverage() {
        Map<FindingEvaluationMetrics.Dimension, FindingEvaluationMetrics.Result> results =
                FindingEvaluationMetrics.evaluateCases(List.of(
                        new FindingEvaluationMetrics.EvaluationCase(
                                "sql-positive-1", "SQL_INJECTION", "NATIVE", true,
                                FindingEvaluationMetrics.Outcome.EXECUTED, true),
                        new FindingEvaluationMetrics.EvaluationCase(
                                "sql-negative-1", "SQL_INJECTION", "NATIVE", false,
                                FindingEvaluationMetrics.Outcome.EXECUTED, true),
                        new FindingEvaluationMetrics.EvaluationCase(
                                "sql-negative-2", "SQL_INJECTION", "NATIVE", false,
                                FindingEvaluationMetrics.Outcome.EXECUTED, false),
                        new FindingEvaluationMetrics.EvaluationCase(
                                "sql-positive-2", "SQL_INJECTION", "NATIVE", true,
                                FindingEvaluationMetrics.Outcome.SKIPPED, false),
                        new FindingEvaluationMetrics.EvaluationCase(
                                "sql-positive-1", "SQL_INJECTION", "OWASP_ZAP", true,
                                FindingEvaluationMetrics.Outcome.EXECUTED, false),
                        new FindingEvaluationMetrics.EvaluationCase(
                                "sql-negative-1", "SQL_INJECTION", "OWASP_ZAP", false,
                                FindingEvaluationMetrics.Outcome.EXECUTED, false),
                        new FindingEvaluationMetrics.EvaluationCase(
                                "sql-negative-2", "SQL_INJECTION", "OWASP_ZAP", false,
                                FindingEvaluationMetrics.Outcome.EXECUTED, false),
                        new FindingEvaluationMetrics.EvaluationCase(
                                "sql-positive-2", "SQL_INJECTION", "OWASP_ZAP", true,
                                FindingEvaluationMetrics.Outcome.UNSUPPORTED, false),
                        new FindingEvaluationMetrics.EvaluationCase(
                                "cookie-configuration-1", "COOKIE_SECURITY", "NATIVE", false,
                                FindingEvaluationMetrics.Outcome.FAILED, false)
                ));

        FindingEvaluationMetrics.Result nativeResults = results.get(
                new FindingEvaluationMetrics.Dimension("SQL_INJECTION", "NATIVE"));
        assertEquals(1, nativeResults.truePositive());
        assertEquals(1, nativeResults.falsePositive());
        assertEquals(0, nativeResults.falseNegative());
        assertEquals(1, nativeResults.trueNegative());
        assertEquals(OptionalDouble.of(0.75), nativeResults.detectionCoverage());
        assertEquals(1, nativeResults.skippedCases());
        assertEquals(0, nativeResults.unsupportedCases());
        assertEquals(0, nativeResults.failedCases());

        FindingEvaluationMetrics.Result zapResults = results.get(
                new FindingEvaluationMetrics.Dimension("SQL_INJECTION", "OWASP_ZAP"));
        assertEquals(0, zapResults.truePositive());
        assertEquals(0, zapResults.falsePositive());
        assertEquals(1, zapResults.falseNegative());
        assertEquals(2, zapResults.trueNegative());
        assertEquals(OptionalDouble.of(0.75), zapResults.detectionCoverage());
        assertEquals(0, zapResults.skippedCases());
        assertEquals(1, zapResults.unsupportedCases());
        assertEquals(0, zapResults.failedCases());

        FindingEvaluationMetrics.Result cookieResults = results.get(
                new FindingEvaluationMetrics.Dimension("COOKIE_SECURITY", "NATIVE"));
        assertEquals(1, cookieResults.failedCases());
        assertEquals(0, cookieResults.executedCases());
        assertEquals(OptionalDouble.of(0.0), cookieResults.detectionCoverage());
        assertEquals(OptionalDouble.empty(), cookieResults.accuracy());
    }

    @Test
    void rejectsDuplicateCaseRowsAndDetectionsForUnexecutedCases() {
        FindingEvaluationMetrics.EvaluationCase row = new FindingEvaluationMetrics.EvaluationCase(
                "case-1", "XSS", "NATIVE", true, FindingEvaluationMetrics.Outcome.EXECUTED, false);
        assertThrows(IllegalArgumentException.class, () ->
                FindingEvaluationMetrics.evaluateCases(List.of(row, row)));
        assertThrows(IllegalArgumentException.class, () ->
                FindingEvaluationMetrics.evaluateCases(List.of(
                        new FindingEvaluationMetrics.EvaluationCase(
                                "case-2", "XSS", "NATIVE", true,
                                FindingEvaluationMetrics.Outcome.SKIPPED, true))));
        assertThrows(IllegalArgumentException.class, () ->
                FindingEvaluationMetrics.evaluateCases(List.of(
                        new FindingEvaluationMetrics.EvaluationCase(
                                "case-3", "XSS", "NATIVE", null,
                                FindingEvaluationMetrics.Outcome.EXECUTED, false))));
    }
}
