package com.vulnscanner.application.dashboard;

import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.scan.ScanFindingRepository;
import com.vulnscanner.application.scan.ScanJobRepository;
import com.vulnscanner.application.target.TargetAnalystAssignmentRepository;
import com.vulnscanner.application.target.TargetStatus;
import com.vulnscanner.application.scan.ScanStatus;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class DashboardAnalyticsService {
    private static final int MAX_DAYS = 90;

    private final OrganizationRepository organizationRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanFindingRepository scanFindingRepository;
    private final TargetAnalystAssignmentRepository assignmentRepository;

    public DashboardAnalyticsService(OrganizationRepository organizationRepository,
                                     ScanJobRepository scanJobRepository,
                                     ScanFindingRepository scanFindingRepository,
                                     TargetAnalystAssignmentRepository assignmentRepository) {
        this.organizationRepository = organizationRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanFindingRepository = scanFindingRepository;
        this.assignmentRepository = assignmentRepository;
    }

    @Transactional(readOnly = true)
    public DashboardAnalyticsResponse platform(int days) {
        DateRange range = dateRange(days);
        Map<LocalDate, PointBuilder> points = emptyPoints(range);
        for (Object[] row : organizationRepository.countDailyRegistrations(range.start(), range.end())) {
            points.get(date(row[0])).organizationsRegistered = number(row[1]);
        }
        return response("PLATFORM", range, points);
    }

    @Transactional(readOnly = true)
    public DashboardAnalyticsResponse organization(Long organizationId, int days) {
        DateRange range = dateRange(days);
        Map<LocalDate, PointBuilder> points = emptyPoints(range);
        addScans(scanJobRepository.countDailyByOrganization(
                organizationId, range.start(), range.end()), points);
        addFindings(scanFindingRepository.countDailySeverityByOrganization(
                organizationId, range.start(), range.end()), points);
        return response("ORGANIZATION", range, points);
    }

    @Transactional(readOnly = true)
    public DashboardAnalyticsResponse analyst(Long analystId, Long organizationId, int days) {
        DateRange range = dateRange(days);
        Map<LocalDate, PointBuilder> points = emptyPoints(range);
        List<Long> assignedTargetIds = assignmentRepository.findAssignedTargetIds(
                analystId, organizationId, TargetStatus.APPROVED);
        if (!assignedTargetIds.isEmpty()) {
            addScans(scanJobRepository.countDailyByAssignedTargets(
                    organizationId, assignedTargetIds, range.start(), range.end()), points);
            addFindings(scanFindingRepository.countDailySeverityByAssignedTargets(
                    organizationId, assignedTargetIds, range.start(), range.end()), points);
        }
        return response("ANALYST", range, points);
    }

    private void addScans(List<Object[]> rows, Map<LocalDate, PointBuilder> points) {
        for (Object[] row : rows) {
            PointBuilder point = points.get(date(row[0]));
            long count = number(row[2]);
            point.scans += count;
            String status = row[1] instanceof Enum<?> value ? value.name() : String.valueOf(row[1]);
            if (ScanStatus.COMPLETED.name().equals(status)) {
                point.completedScans += count;
            } else if (ScanStatus.FAILED.name().equals(status)) {
                point.failedScans += count;
            }
        }
    }

    private void addFindings(List<Object[]> rows, Map<LocalDate, PointBuilder> points) {
        for (Object[] row : rows) {
            PointBuilder point = points.get(date(row[0]));
            String severity = String.valueOf(row[1]);
            long count = number(row[2]);
            switch (severity.toUpperCase(java.util.Locale.ROOT)) {
                case "HIGH" -> point.highFindings += count;
                case "MEDIUM" -> point.mediumFindings += count;
                case "LOW" -> point.lowFindings += count;
                default -> {
                }
            }
        }
    }

    private Map<LocalDate, PointBuilder> emptyPoints(DateRange range) {
        Map<LocalDate, PointBuilder> points = new HashMap<>();
        for (LocalDate day = range.from(); !day.isAfter(range.through()); day = day.plusDays(1)) {
            points.put(day, new PointBuilder());
        }
        return points;
    }

    private DashboardAnalyticsResponse response(String scope, DateRange range,
                                                 Map<LocalDate, PointBuilder> points) {
        List<DailyDashboardPoint> dailyPoints = new ArrayList<>(points.size());
        points.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            PointBuilder point = entry.getValue();
            dailyPoints.add(new DailyDashboardPoint(entry.getKey(), point.organizationsRegistered,
                    point.scans, point.completedScans, point.failedScans, point.highFindings,
                    point.mediumFindings, point.lowFindings));
        });
        return new DashboardAnalyticsResponse(scope, range.from(), range.through(), List.copyOf(dailyPoints));
    }

    private DateRange dateRange(int days) {
        if (days < 1 || days > MAX_DAYS) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Analytics range must be between 1 and " + MAX_DAYS + " days");
        }
        LocalDate through = LocalDate.now(ZoneOffset.UTC);
        LocalDate from = through.minusDays(days - 1L);
        return new DateRange(from, through, from.atStartOfDay().toInstant(ZoneOffset.UTC),
                through.plusDays(1).atStartOfDay().toInstant(ZoneOffset.UTC));
    }

    private LocalDate date(Object value) {
        if (value instanceof LocalDate localDate) {
            return localDate;
        }
        if (value instanceof java.sql.Date sqlDate) {
            return sqlDate.toLocalDate();
        }
        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant().atZone(ZoneOffset.UTC).toLocalDate();
        }
        if (value instanceof Instant instant) {
            return instant.atZone(ZoneOffset.UTC).toLocalDate();
        }
        return LocalDate.parse(value.toString());
    }

    private long number(Object value) {
        return ((Number) value).longValue();
    }

    private record DateRange(LocalDate from, LocalDate through, Instant start, Instant end) {
    }

    private static final class PointBuilder {
        private long organizationsRegistered;
        private long scans;
        private long completedScans;
        private long failedScans;
        private long highFindings;
        private long mediumFindings;
        private long lowFindings;
    }
}
