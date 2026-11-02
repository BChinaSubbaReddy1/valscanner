package com.vulnscanner.application.scan;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalDouble;
import java.util.Set;

final class FindingEvaluationMetrics {
    private FindingEvaluationMetrics() {
    }

    static Result evaluate(Set<String> referenceUniverse, Set<String> verifiedFindings,
                           Set<String> observedFindings) {
        Objects.requireNonNull(referenceUniverse);
        Objects.requireNonNull(verifiedFindings);
        Objects.requireNonNull(observedFindings);
        if (!referenceUniverse.containsAll(verifiedFindings)
                || !referenceUniverse.containsAll(observedFindings)) {
            throw new IllegalArgumentException("Finding instances must belong to the reference universe");
        }

        int truePositive = (int) observedFindings.stream().filter(verifiedFindings::contains).count();
        int falsePositive = observedFindings.size() - truePositive;
        int falseNegative = verifiedFindings.size() - truePositive;
        int trueNegative = referenceUniverse.size() - truePositive - falsePositive - falseNegative;
        return new Result(truePositive, falsePositive, falseNegative, trueNegative,
                referenceUniverse.size(), referenceUniverse.size(), 0, 0, 0);
    }

    static Map<Dimension, Result> evaluateCases(List<EvaluationCase> cases) {
        Objects.requireNonNull(cases);
        Map<Dimension, MutableCounts> grouped = new LinkedHashMap<>();
        Set<String> uniqueCases = new java.util.HashSet<>();
        for (EvaluationCase evaluationCase : cases) {
            Objects.requireNonNull(evaluationCase);
            if (isBlank(evaluationCase.caseId()) || isBlank(evaluationCase.category())
                    || isBlank(evaluationCase.engine()) || evaluationCase.expectedPositive() == null
                    || evaluationCase.outcome() == null) {
                throw new IllegalArgumentException(
                        "Case ID, category, engine, expected label, and outcome are required");
            }
            String uniqueKey = evaluationCase.category() + "\u0000"
                    + evaluationCase.engine() + "\u0000" + evaluationCase.caseId();
            if (!uniqueCases.add(uniqueKey)) {
                throw new IllegalArgumentException("Duplicate case for category and engine");
            }
            if (evaluationCase.outcome() != Outcome.EXECUTED && evaluationCase.detected()) {
                throw new IllegalArgumentException("An unexecuted case cannot have a detection");
            }

            MutableCounts counts = grouped.computeIfAbsent(
                    new Dimension(evaluationCase.category(), evaluationCase.engine()),
                    ignored -> new MutableCounts());
            counts.planned++;
            switch (evaluationCase.outcome()) {
                case SKIPPED -> counts.skipped++;
                case UNSUPPORTED -> counts.unsupported++;
                case FAILED -> counts.failed++;
                case EXECUTED -> counts.executed++;
            }
            if (evaluationCase.outcome() != Outcome.EXECUTED) {
                continue;
            }
            if (evaluationCase.expectedPositive() && evaluationCase.detected()) {
                counts.truePositive++;
            } else if (!evaluationCase.expectedPositive() && evaluationCase.detected()) {
                counts.falsePositive++;
            } else if (evaluationCase.expectedPositive()) {
                counts.falseNegative++;
            } else {
                counts.trueNegative++;
            }
        }

        Map<Dimension, Result> results = new LinkedHashMap<>();
        grouped.forEach((dimension, counts) -> results.put(dimension,
                new Result(counts.truePositive, counts.falsePositive,
                        counts.falseNegative, counts.trueNegative,
                        counts.executed, counts.planned,
                        counts.skipped, counts.unsupported, counts.failed)));
        return Map.copyOf(results);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    enum Outcome {
        EXECUTED,
        SKIPPED,
        UNSUPPORTED,
        FAILED
    }

    record EvaluationCase(String caseId, String category, String engine,
                          Boolean expectedPositive, Outcome outcome, boolean detected) {
    }

    record Dimension(String category, String engine) {
    }

    private static final class MutableCounts {
        private int truePositive;
        private int falsePositive;
        private int falseNegative;
        private int trueNegative;
        private int executed;
        private int planned;
        private int skipped;
        private int unsupported;
        private int failed;
    }

    record Result(int truePositive, int falsePositive, int falseNegative, int trueNegative,
                  int executedCases, int plannedCases, int skippedCases,
                  int unsupportedCases, int failedCases) {
        OptionalDouble precision() {
            return ratio(truePositive, truePositive + falsePositive);
        }

        OptionalDouble recall() {
            return ratio(truePositive, truePositive + falseNegative);
        }

        OptionalDouble accuracy() {
            return ratio(truePositive + trueNegative,
                    truePositive + falsePositive + falseNegative + trueNegative);
        }

        OptionalDouble falsePositiveRate() {
            return ratio(falsePositive, falsePositive + trueNegative);
        }

        OptionalDouble falseNegativeRate() {
            return ratio(falseNegative, falseNegative + truePositive);
        }

        OptionalDouble f1Score() {
            return ratio(2 * truePositive, 2 * truePositive + falsePositive + falseNegative);
        }

        OptionalDouble detectionCoverage() {
            return ratio(executedCases, plannedCases);
        }

        private OptionalDouble ratio(int numerator, int denominator) {
            return denominator == 0
                    ? OptionalDouble.empty()
                    : OptionalDouble.of((double) numerator / denominator);
        }
    }
}
