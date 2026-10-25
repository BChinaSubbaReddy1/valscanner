package com.vulnscanner.application.scan;

import com.vulnscanner.application.audit.AuditEvent;
import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.target.Target;
import com.vulnscanner.application.target.TargetRepository;
import com.vulnscanner.application.target.TargetStatus;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.concurrent.RejectedExecutionException;

@Service
public class ScanService {
    private final ScanJobRepository scanJobRepository;
    private final ScanFindingRepository scanFindingRepository;
    private final ScanCrawlPageRepository scanCrawlPageRepository;
    private final TargetRepository targetRepository;
    private final UserRepository userRepository;
    private final AuditEventRepository auditEventRepository;
    private final ScanExecutionService scanExecutionService;
    private final ThreadPoolTaskExecutor scanTaskExecutor;

    public ScanService(ScanJobRepository scanJobRepository, ScanFindingRepository scanFindingRepository,
                       TargetRepository targetRepository, UserRepository userRepository,
                       AuditEventRepository auditEventRepository, ScanExecutionService scanExecutionService,
                       ThreadPoolTaskExecutor scanTaskExecutor, ScanCrawlPageRepository scanCrawlPageRepository) {
        this.scanJobRepository = scanJobRepository;
        this.scanFindingRepository = scanFindingRepository;
        this.targetRepository = targetRepository;
        this.userRepository = userRepository;
        this.auditEventRepository = auditEventRepository;
        this.scanExecutionService = scanExecutionService;
        this.scanTaskExecutor = scanTaskExecutor;
        this.scanCrawlPageRepository = scanCrawlPageRepository;
    }

    @Transactional
    public ScanJobResponse create(ScanCreateRequest request) {
        User actor = requireOperationalUser();
        if (actor.getRoles().stream().noneMatch(role -> role.getName() == RoleName.SECURITY_ANALYST)) {
            throw new AccessDeniedException("Only Security Analysts can submit scan requests");
        }
        Organization organization = actor.getOrganization();
        Target target = targetRepository.findByIdAndOrganization_IdAndStatus(
                        request.targetId(), organization.getId(), TargetStatus.APPROVED)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Approved target not found"));
        if (request.scanType() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported scan type");
        }
        ScanJob job = new ScanJob(target, organization, actor, request.scanType());
        job.transitionTo(ScanStatus.PENDING_APPROVAL, 0, "Awaiting Organization Admin approval", null);
        job = scanJobRepository.save(job);
        audit("SCAN_JOB_CREATED", job, actor);
        return response(job);
    }

    @Transactional(readOnly = true)
    public Page<ScanJobResponse> list(Pageable pageable) {
        User actor = requireOperationalUser();
        Page<ScanJob> jobs = actor.getRoles().stream().anyMatch(role -> role.getName() == RoleName.ADMIN)
                ? scanJobRepository.findByOrganization_IdOrderByCreatedAtDesc(actor.getOrganization().getId(), pageable)
                : scanJobRepository.findByRequestedBy_IdOrderByCreatedAtDesc(actor.getId(), pageable);
        return jobs
                .map(this::response);
    }

    @Transactional(readOnly = true)
    public AnalystDashboardResponse analystDashboard() {
        User actor = requireOperationalUser();
        if (actor.getRoles().stream().noneMatch(role -> role.getName() == RoleName.SECURITY_ANALYST)) {
            throw new AccessDeniedException("Security Analyst role required");
        }
        Long organizationId = actor.getOrganization().getId();
        return new AnalystDashboardResponse(
                targetRepository.countByOrganization_IdAndStatus(organizationId, TargetStatus.APPROVED),
                scanJobRepository.countByRequestedBy_IdAndStatus(actor.getId(), ScanStatus.PENDING_APPROVAL),
                scanJobRepository.countByRequestedBy_IdAndStatus(actor.getId(), ScanStatus.QUEUED),
                scanJobRepository.countByRequestedBy_IdAndStatus(actor.getId(), ScanStatus.CRAWLING),
                scanJobRepository.countByRequestedBy_IdAndStatus(actor.getId(), ScanStatus.SCANNING),
                scanJobRepository.countByRequestedBy_IdAndStatus(actor.getId(), ScanStatus.RUNNING),
                scanJobRepository.countByRequestedBy_IdAndStatus(actor.getId(), ScanStatus.COMPLETED),
                scanJobRepository.countByRequestedBy_IdAndStatus(actor.getId(), ScanStatus.FAILED),
                scanJobRepository.countByRequestedBy_IdAndStatus(actor.getId(), ScanStatus.CANCELLED),
                scanJobRepository.countByRequestedBy_IdAndStatus(actor.getId(), ScanStatus.REJECTED),
                scanFindingRepository.countByRequesterAndSeverity(actor.getId(), "HIGH"),
                scanFindingRepository.countByRequesterAndSeverity(actor.getId(), "MEDIUM"),
                scanFindingRepository.countByRequesterAndSeverity(actor.getId(), "LOW"));
    }

    @Transactional(readOnly = true)
    public Page<ScanJobResponse> pendingApprovals(Pageable pageable) {
        User actor = requireAdmin();
        return scanJobRepository.findByOrganization_IdAndStatusOrderByCreatedAtAsc(
                        actor.getOrganization().getId(), ScanStatus.PENDING_APPROVAL, pageable)
                .map(this::response);
    }

    @Transactional
    public ScanJobResponse approve(Long scanId) {
        User reviewer = requireAdmin();
        ScanJob job = findForAdminUpdate(scanId, reviewer);
        try {
            job.approve(reviewer);
        } catch (IllegalStateException exception) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, exception.getMessage());
        }
        ScanJob saved = scanJobRepository.saveAndFlush(job);
        audit("SCAN_JOB_APPROVED", saved, reviewer);
        enqueueAfterCommit(saved.getId());
        return response(saved);
    }

    @Transactional
    public ScanJobResponse reject(Long scanId, ScanRejectRequest request) {
        User reviewer = requireAdmin();
        ScanJob job = findForAdminUpdate(scanId, reviewer);
        try {
            job.reject(reviewer, request.reason());
        } catch (IllegalStateException exception) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, exception.getMessage());
        }
        ScanJob saved = scanJobRepository.save(job);
        audit("SCAN_JOB_REJECTED", saved, reviewer);
        return response(saved);
    }

    @Transactional(readOnly = true)
    public ScanJobResponse get(Long scanId) {
        return response(findAccessible(scanId));
    }

    @Transactional
    public ScanJobResponse cancel(Long scanId) {
        User actor = requireOperationalUser();
        ScanJob job = findAccessible(scanId);
        try {
            job.requestCancellation();
        } catch (IllegalStateException exception) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, exception.getMessage());
        }
        ScanJob saved = scanJobRepository.save(job);
        audit("SCAN_JOB_CANCELLED", saved, actor);
        return response(saved);
    }

    @Transactional(readOnly = true)
    public List<ScanFindingResponse> findings(Long scanId) {
        User actor = requireOperationalUser();
        ScanJob job = findAccessible(scanId);
        if (job.getStatus() != ScanStatus.COMPLETED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Findings are available after scan completion");
        }
        return scanFindingRepository
                .findByScanJob_IdAndScanJob_Organization_IdOrderByDetectedAtDesc(
                        scanId, actor.getOrganization().getId())
                .stream().map(this::findingResponse).toList();
    }

    @Transactional(readOnly = true)
    public List<ScanCrawlPageResponse> crawlPages(Long scanId) {
        findAccessible(scanId);
        return scanCrawlPageRepository.findByScanJob_IdOrderByDepthAscUrlAsc(scanId)
                .stream()
                .map(page -> new ScanCrawlPageResponse(page.getId(), page.getUrl(), page.getDepth(),
                        page.getStatusCode(), page.getResponseBytes(), page.getDiscoveredLinks(),
                        page.getDiscoveredForms(), page.getDiscoveredAt()))
                .toList();
    }

    private ScanJob findAccessible(Long scanId) {
        User actor = requireOperationalUser();
        boolean isAdmin = actor.getRoles().stream().anyMatch(role -> role.getName() == RoleName.ADMIN);
        return (isAdmin
                ? scanJobRepository.findByIdAndOrganization_Id(scanId, actor.getOrganization().getId())
                : scanJobRepository.findByIdAndRequestedBy_Id(scanId, actor.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
    }

    private ScanJob findForAdminUpdate(Long scanId, User admin) {
        return scanJobRepository.findByIdAndOrganizationForUpdate(scanId, admin.getOrganization().getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
    }

    private User requireAdmin() {
        User actor = requireOperationalUser();
        if (actor.getRoles().stream().noneMatch(role -> role.getName() == RoleName.ADMIN)) {
            throw new AccessDeniedException("Organization Admin role required");
        }
        return actor;
    }

    private void enqueueAfterCommit(Long scanId) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    scanTaskExecutor.execute(() -> scanExecutionService.execute(scanId));
                } catch (RejectedExecutionException exception) {
                    scanExecutionService.markRejected(scanId);
                }
            }
        });
    }

    private User requireOperationalUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required");
        }
        User actor = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new AccessDeniedException("Authentication required"));
        if (actor.getStatus() != UserStatus.ACTIVE) {
            throw new AccessDeniedException("Active account required");
        }
        Organization organization = actor.getOrganization();
        if (organization == null || organization.getStatus() != OrganizationStatus.APPROVED) {
            throw new AccessDeniedException("An approved organization membership is required");
        }
        boolean allowedRole = actor.getRoles().stream().anyMatch(role ->
                role.getName() == RoleName.ADMIN || role.getName() == RoleName.SECURITY_ANALYST);
        if (!allowedRole) {
            throw new AccessDeniedException("Insufficient role");
        }
        return actor;
    }

    private ScanJobResponse response(ScanJob job) {
        return new ScanJobResponse(job.getId(), job.getTarget().getId(), job.getTarget().getName(),
                job.getScanType(), job.getStatus(), job.getProgress(), job.getStatusMessage(),
                job.getFailureReason(), job.isCancellationRequested(), job.getCreatedAt(),
                job.getStartedAt(), job.getCompletedAt(),
                job.getReviewedBy() == null ? null : job.getReviewedBy().getId(),
                job.getReviewedAt(), job.getRejectionReason(), ScanExecutionSummary.from(job));
    }

    private ScanFindingResponse findingResponse(ScanFinding finding) {
        return new ScanFindingResponse(finding.getId(), finding.getCheckType(), finding.getSeverity(),
                FindingSanitizer.sanitize(finding.getAffectedComponent()),
                FindingSanitizer.sanitize(finding.getEvidence()),
                FindingSanitizer.sanitize(finding.getRationale()),
                FindingSanitizer.sanitize(finding.getRemediation()),
                finding.getDetectionSource(), finding.getVerificationStatus(),
                finding.getDetectedAt(), finding.getSourceRuleId(), finding.getSourceConfidence(),
                finding.getSourceReference(), finding.getSourceCweId(), finding.getSourceWascId());
    }

    private void audit(String eventType, ScanJob job, User actor) {
        AuditEvent event = new AuditEvent();
        event.setEventType(eventType);
        event.setEventLevel("INFO");
        event.setMessage("Scan job " + job.getId() + " " + eventType.toLowerCase().replace('_', ' '));
        event.setOrganization(job.getOrganization());
        event.setActor(actor);
        auditEventRepository.save(event);
    }
}
