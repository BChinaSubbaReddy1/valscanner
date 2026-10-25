package com.vulnscanner.application.scan;

import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.target.Target;
import com.vulnscanner.application.user.User;
import jakarta.persistence.*;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

@Entity
@Table(name = "scan_jobs", indexes = {
        @Index(name = "idx_scan_jobs_org_created", columnList = "organization_id,created_at"),
        @Index(name = "idx_scan_jobs_target", columnList = "target_id")
})
public class ScanJob {
    private static final Map<ScanStatus, Set<ScanStatus>> ALLOWED_TRANSITIONS = Map.of(
            ScanStatus.CREATED, EnumSet.of(ScanStatus.PENDING_APPROVAL, ScanStatus.QUEUED,
                    ScanStatus.CANCELLED, ScanStatus.FAILED),
            ScanStatus.PENDING_APPROVAL, EnumSet.of(ScanStatus.QUEUED, ScanStatus.CANCELLED, ScanStatus.REJECTED),
            ScanStatus.QUEUED, EnumSet.of(ScanStatus.RUNNING, ScanStatus.CRAWLING, ScanStatus.CANCELLED, ScanStatus.FAILED),
            ScanStatus.CRAWLING, EnumSet.of(ScanStatus.SCANNING, ScanStatus.CANCELLED, ScanStatus.FAILED),
            ScanStatus.SCANNING, EnumSet.of(ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED),
            ScanStatus.RUNNING, EnumSet.of(ScanStatus.CRAWLING, ScanStatus.SCANNING,
                    ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED),
            ScanStatus.COMPLETED, EnumSet.noneOf(ScanStatus.class),
            ScanStatus.FAILED, EnumSet.noneOf(ScanStatus.class),
            ScanStatus.CANCELLED, EnumSet.noneOf(ScanStatus.class),
            ScanStatus.REJECTED, EnumSet.noneOf(ScanStatus.class));

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "target_id", nullable = false)
    private Target target;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "organization_id", nullable = false)
    private Organization organization;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "requested_by_user_id", nullable = false)
    private User requestedBy;

    @Enumerated(EnumType.STRING)
    @Column(name = "scan_type", nullable = false, length = 32)
    private ScanType scanType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private ScanStatus status = ScanStatus.CREATED;

    @Column(nullable = false)
    private int progress = 0;

    @Column(name = "status_message", nullable = false, length = 250)
    private String statusMessage = "Awaiting passive scanner availability";

    @Column(name = "failure_reason", length = 250)
    private String failureReason;

    @Column(name = "cancellation_requested", nullable = false)
    private boolean cancellationRequested;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reviewed_by_user_id")
    private User reviewedBy;

    @Column(name = "reviewed_at")
    private Instant reviewedAt;

    @Column(name = "rejection_reason", length = 1000)
    private String rejectionReason;

    @Column(name = "native_engine_status", nullable = false, length = 24)
    private String nativeEngineStatus = "NOT_STARTED";

    @Column(name = "zap_engine_status", nullable = false, length = 24)
    private String zapEngineStatus = "UNKNOWN";

    @Column(name = "discovered_page_count")
    private Integer discoveredPageCount;

    @Column(name = "visited_page_count")
    private Integer visitedPageCount;

    @Column(name = "tested_passive_page_count")
    private Integer testedPassivePageCount;

    protected ScanJob() {
    }

    public ScanJob(Target target, Organization organization, User requestedBy, ScanType scanType) {
        this.target = target;
        this.organization = organization;
        this.requestedBy = requestedBy;
        this.scanType = scanType;
        this.zapEngineStatus = scanType == ScanType.PASSIVE_HEADERS ? "NOT_REQUESTED" : "NOT_STARTED";
    }

    public void transitionTo(ScanStatus nextStatus, int nextProgress, String safeMessage,
                             ScanFailureReason safeFailureReason) {
        if (!ALLOWED_TRANSITIONS.get(status).contains(nextStatus)) {
            throw new IllegalStateException("Invalid scan lifecycle transition");
        }
        if (nextProgress < progress || nextProgress < 0 || nextProgress > 100) {
            throw new IllegalArgumentException("Scan progress must be between the current progress and 100");
        }
        if (safeMessage == null || safeMessage.isBlank() || safeMessage.length() > 250) {
            throw new IllegalArgumentException("A safe status message is required");
        }
        if (nextStatus == ScanStatus.FAILED && safeFailureReason == null) {
            throw new IllegalArgumentException("A safe failure reason is required");
        }
        if (nextStatus != ScanStatus.FAILED && safeFailureReason != null) {
            throw new IllegalArgumentException("Failure reason is only allowed for failed scans");
        }
        status = nextStatus;
        progress = nextProgress;
        statusMessage = safeMessage;
        failureReason = safeFailureReason == null ? null : safeFailureReason.name();
        Instant now = Instant.now();
        if ((nextStatus == ScanStatus.RUNNING || nextStatus == ScanStatus.CRAWLING) && startedAt == null) {
            startedAt = now;
        }
        if (EnumSet.of(ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED, ScanStatus.REJECTED)
                .contains(nextStatus)) {
            completedAt = now;
        }
    }

    public void updateProgress(int nextProgress, String safeMessage) {
        if (nextProgress < progress || nextProgress < 0 || nextProgress > 100) {
            throw new IllegalArgumentException("Scan progress must be between the current progress and 100");
        }
        if (safeMessage == null || safeMessage.isBlank() || safeMessage.length() > 250) {
            throw new IllegalArgumentException("A safe status message is required");
        }
        this.progress = nextProgress;
        this.statusMessage = safeMessage;
    }

    void mergeExecutionState(ScanJob update) {
        if (EnumSet.of(ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED, ScanStatus.REJECTED)
                .contains(status)) {
            return;
        }
        copyExecutionDetailsFrom(update);
        if (cancellationRequested && update.status != ScanStatus.CANCELLED) {
            requestCancellation();
            if (status != ScanStatus.CANCELLED) {
                transitionTo(ScanStatus.CANCELLED, progress, "Scan cancelled during execution", null);
            }
        } else if (status == update.status) {
            updateProgress(update.progress, update.statusMessage);
        } else {
            ScanFailureReason reason = update.failureReason == null
                    ? null : ScanFailureReason.valueOf(update.failureReason);
            transitionTo(update.status, update.progress, update.statusMessage, reason);
        }
    }

    void copyExecutionStateFrom(ScanJob source) {
        status = source.status;
        progress = source.progress;
        statusMessage = source.statusMessage;
        failureReason = source.failureReason;
        cancellationRequested = source.cancellationRequested;
        startedAt = source.startedAt;
        completedAt = source.completedAt;
        copyExecutionDetailsFrom(source);
    }

    private void copyExecutionDetailsFrom(ScanJob source) {
        nativeEngineStatus = source.nativeEngineStatus;
        zapEngineStatus = source.zapEngineStatus;
        discoveredPageCount = source.discoveredPageCount;
        visitedPageCount = source.visitedPageCount;
        testedPassivePageCount = source.testedPassivePageCount;
    }

    public void updateNativeEngineStatus(String nextStatus) {
        nativeEngineStatus = requireEngineStatus(nextStatus);
    }

    public void updateZapEngineStatus(String nextStatus) {
        zapEngineStatus = requireEngineStatus(nextStatus);
    }

    public void updateCrawlCounts(int discovered, int visited, int passiveTested) {
        if (discovered < 0 || visited < 0 || passiveTested < 0
                || visited > discovered || passiveTested > visited) {
            throw new IllegalArgumentException("Scan page counts must be non-negative and internally consistent");
        }
        discoveredPageCount = discovered;
        visitedPageCount = visited;
        testedPassivePageCount = passiveTested;
    }

    private String requireEngineStatus(String value) {
        if (value == null || value.isBlank() || value.length() > 24) {
            throw new IllegalArgumentException("A valid engine status is required");
        }
        return value;
    }

    public void requestCancellation() {
        if (status == ScanStatus.PENDING_APPROVAL) {
            cancellationRequested = true;
            transitionTo(ScanStatus.CANCELLED, progress, "Scan request cancelled before approval", null);
            return;
        }
        if (status == ScanStatus.RUNNING || status == ScanStatus.CRAWLING || status == ScanStatus.SCANNING) {
            cancellationRequested = true;
            statusMessage = "Cancellation requested; current HTTP operation will stop at its timeout";
            return;
        }
        if (status != ScanStatus.CREATED && status != ScanStatus.QUEUED) {
            throw new IllegalStateException("Scan is already in a terminal state");
        }
        cancellationRequested = true;
        transitionTo(ScanStatus.CANCELLED, progress, "Scan cancelled before execution", null);
    }

    public void approve(User reviewer) {
        if (status != ScanStatus.PENDING_APPROVAL) {
            throw new IllegalStateException("Only pending scan requests can be approved");
        }
        reviewedBy = reviewer;
        reviewedAt = Instant.now();
        transitionTo(ScanStatus.QUEUED, 0, "Scan approved and queued", null);
    }

    public void reject(User reviewer, String reason) {
        if (status != ScanStatus.PENDING_APPROVAL) {
            throw new IllegalStateException("Only pending scan requests can be rejected");
        }
        if (reason == null || reason.isBlank() || reason.trim().length() > 1000) {
            throw new IllegalArgumentException("A rejection reason is required");
        }
        reviewedBy = reviewer;
        reviewedAt = Instant.now();
        rejectionReason = reason.trim();
        transitionTo(ScanStatus.REJECTED, progress, "Scan request rejected", null);
    }

    public Long getId() { return id; }
    public Target getTarget() { return target; }
    public Organization getOrganization() { return organization; }
    public User getRequestedBy() { return requestedBy; }
    public ScanType getScanType() { return scanType; }
    public ScanStatus getStatus() { return status; }
    public int getProgress() { return progress; }
    public String getStatusMessage() { return statusMessage; }
    public String getFailureReason() { return failureReason; }
    public boolean isCancellationRequested() { return cancellationRequested; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getStartedAt() { return startedAt; }
    public Instant getCompletedAt() { return completedAt; }
    public User getReviewedBy() { return reviewedBy; }
    public Instant getReviewedAt() { return reviewedAt; }
    public String getRejectionReason() { return rejectionReason; }
    public String getNativeEngineStatus() { return nativeEngineStatus; }
    public String getZapEngineStatus() { return zapEngineStatus; }
    public Integer getDiscoveredPageCount() { return discoveredPageCount; }
    public Integer getVisitedPageCount() { return visitedPageCount; }
    public Integer getTestedPassivePageCount() { return testedPassivePageCount; }
}
