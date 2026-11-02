package com.vulnscanner.application.dashboard;

import java.time.LocalDate;

public record DailyDashboardPoint(
        LocalDate date,
        long organizationsRegistered,
        long scans,
        long completedScans,
        long failedScans,
        long highFindings,
        long mediumFindings,
        long lowFindings
) {
}
