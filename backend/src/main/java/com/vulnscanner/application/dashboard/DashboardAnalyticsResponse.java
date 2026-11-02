package com.vulnscanner.application.dashboard;

import java.time.LocalDate;
import java.util.List;

public record DashboardAnalyticsResponse(
        String scope,
        LocalDate from,
        LocalDate through,
        List<DailyDashboardPoint> points
) {
}
