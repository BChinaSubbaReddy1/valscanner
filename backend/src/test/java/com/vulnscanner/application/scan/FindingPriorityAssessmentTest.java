package com.vulnscanner.application.scan;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingPriorityAssessmentTest {
    @Test
    void derivesTechnicalPriorityFromOnlyObservedSeverityVerificationAndConfidence() {
        FindingPriorityAssessment assessment =
                FindingPriorityAssessment.assess("HIGH", "POTENTIAL", "HIGH");

        assertEquals(73, assessment.score());
        assertEquals("HIGH", assessment.level());
        assertTrue(assessment.explanation().contains("severity HIGH +60"));
        assertTrue(assessment.explanation().contains("verification POTENTIAL +3"));
        assertTrue(assessment.explanation().contains("source confidence HIGH +10"));
        assertTrue(assessment.explanation().contains("Business impact"));
        assertTrue(assessment.explanation().contains("not CVSS"));
    }

    @Test
    void treatsUnknownFactorsAsUnknownAndDoesNotPromoteOriginalSeverity() {
        FindingPriorityAssessment assessment =
                FindingPriorityAssessment.assess("UNKNOWN", null, "UNAVAILABLE");

        assertEquals(0, assessment.score());
        assertEquals("LOW", assessment.level());
        assertTrue(assessment.explanation().contains("severity UNKNOWN +0"));
        assertTrue(assessment.explanation().contains("verification UNKNOWN +0"));
        assertTrue(assessment.explanation().contains("source confidence UNAVAILABLE +0"));
    }
}
