package com.vulnscanner.application.scan;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdaptiveCheckSelectorTest {
    @Test
    void selectsChecksFromObservedEndpointInputsAndResponseType() {
        AdaptiveCheckSelector.Plan plan = AdaptiveCheckSelector.select(
                ScanType.ZAP_ACTIVE, "https://lab.test/search", "text/html",
                Map.of("content-type", List.of("text/html")), List.of("q"), false, false);

        assertEquals(List.of("SQL_INJECTION", "REFLECTED_XSS"), plan.selectedChecks());
        assertEquals(3, plan.requestsPerParameter());
        assertTrue(plan.rationale().contains("supports a bounded SQL check"));
    }

    @Test
    void observedDatabaseTechnologySelectsSqlCheckForNonSemanticInputNames() {
        AdaptiveCheckSelector.Plan plan = AdaptiveCheckSelector.select(
                ScanType.ZAP_ACTIVE, "https://lab.test/custom", "application/json",
                Map.of("server", List.of("Example MySQL gateway")), List.of("field_1"),
                false, false);

        assertEquals(List.of("mysql"), plan.observedDatabaseTechnology());
        assertEquals(List.of("SQL_INJECTION"), plan.selectedChecks());
        assertEquals(2, plan.requestsPerParameter());
        assertFalse(plan.reflectedXss());
    }

    @Test
    void selectsBoundedSqlCheckForArbitraryObservedInputNames() {
        AdaptiveCheckSelector.Plan getPlan = AdaptiveCheckSelector.select(
                ScanType.ZAP_ACTIVE, "https://lab.test/custom", "application/json",
                Map.of(), List.of("keyboard"), false, false);
        AdaptiveCheckSelector.Plan postPlan = AdaptiveCheckSelector.select(
                ScanType.ZAP_ACTIVE, "https://lab.test/submit", "application/json",
                Map.of(), List.of("entry_42"), true, true);
        AdaptiveCheckSelector.Plan authorPlan = AdaptiveCheckSelector.select(
                ScanType.ZAP_ACTIVE, "https://lab.test/custom", "application/json",
                Map.of(), List.of("author"), false, false);
        AdaptiveCheckSelector.Plan passwordPlan = AdaptiveCheckSelector.select(
                ScanType.ZAP_ACTIVE, "https://lab.test/custom", "application/json",
                Map.of(), List.of("password1"), false, false);

        assertEquals(List.of("SQL_INJECTION"), getPlan.selectedChecks());
        assertEquals(List.of("SQL_INJECTION"), postPlan.selectedChecks());
        assertEquals(List.of("SQL_INJECTION"), authorPlan.selectedChecks());
        assertTrue(passwordPlan.selectedChecks().isEmpty());
        assertEquals(2, getPlan.requestsPerParameter());
        assertTrue(getPlan.rationale().contains("eligible non-sensitive input"));
    }

    @Test
    void passiveModeAndUnapprovedPostFormsNeverSelectActiveChecks() {
        AdaptiveCheckSelector.Plan passive = AdaptiveCheckSelector.select(
                ScanType.PASSIVE_HEADERS, "https://lab.test/search", "text/html",
                Map.of(), List.of("q"), false, false);
        AdaptiveCheckSelector.Plan unapprovedPost = AdaptiveCheckSelector.select(
                ScanType.ZAP_ACTIVE, "https://lab.test/search", "text/html",
                Map.of(), List.of("q"), true, false);

        assertTrue(passive.selectedChecks().isEmpty());
        assertTrue(unapprovedPost.selectedChecks().isEmpty());
        assertTrue(unapprovedPost.rationale().contains("not explicitly allowlisted"));
    }

    @Test
    void neverSelectsReflectionForNonHtmlOrSensitiveInput() {
        AdaptiveCheckSelector.Plan json = AdaptiveCheckSelector.select(
                ScanType.ZAP_ACTIVE, "https://lab.test/search", "application/json",
                Map.of(), List.of("q"), false, false);
        AdaptiveCheckSelector.Plan secret = AdaptiveCheckSelector.select(
                ScanType.ZAP_ACTIVE, "https://lab.test/search", "text/html",
                Map.of(), List.of("sessionToken"), false, false);

        assertEquals(List.of("SQL_INJECTION"), json.selectedChecks());
        assertTrue(secret.selectedChecks().isEmpty());
    }
}
