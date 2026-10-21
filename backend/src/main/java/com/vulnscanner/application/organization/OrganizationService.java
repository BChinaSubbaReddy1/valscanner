package com.vulnscanner.application.organization;

import com.vulnscanner.application.audit.AuditEvent;
import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import com.vulnscanner.application.scan.ScanFindingRepository;
import com.vulnscanner.application.scan.ScanJobRepository;
import com.vulnscanner.application.scan.ScanStatus;
import com.vulnscanner.application.target.TargetRepository;
import com.vulnscanner.application.target.TargetStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.Locale;

@Service
public class OrganizationService {
    private static final Logger log = LoggerFactory.getLogger(OrganizationService.class);
    private static final int MAX_PAGE_SIZE = 100;

    private final OrganizationRepository organizationRepository;
    private final UserRepository userRepository;
    private final AuditEventRepository auditEventRepository;
    private final TargetRepository targetRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanFindingRepository scanFindingRepository;

    public OrganizationService(OrganizationRepository organizationRepository,
                               UserRepository userRepository,
                               AuditEventRepository auditEventRepository,
                               TargetRepository targetRepository,
                               ScanJobRepository scanJobRepository,
                               ScanFindingRepository scanFindingRepository) {
        this.organizationRepository = organizationRepository;
        this.userRepository = userRepository;
        this.auditEventRepository = auditEventRepository;
        this.targetRepository = targetRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanFindingRepository = scanFindingRepository;
    }

    @Transactional
    public Organization register(OrganizationRegistrationRequest request) {
        requireSuperAdmin();
        if (!organizationRepository.findAllByNormalizedName(request.name().trim()).isEmpty()) {
            throw new IllegalArgumentException("Organization already exists");
        }
        Organization org = new Organization();
        org.setName(request.name().trim());
        org.setContactEmail(request.contactEmail().trim().toLowerCase(Locale.ROOT));
        org.setPrimaryContactName(request.primaryContactName().trim());
        org.setStatus(OrganizationStatus.PENDING);
        Organization saved = organizationRepository.save(org);
        audit("ORGANIZATION_REGISTRATION_SUBMITTED", "Organization registration submitted", saved, null, currentUser());
        return saved;
    }

    @Transactional(readOnly = true)
    public OrganizationResponse getOrganizationForAdmin(Long id) {
        requireSuperAdmin();
        Organization org = organizationRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Organization not found"));
        return response(org);
    }

    @Transactional(readOnly = true)
    public List<OrganizationResponse> getPendingOrganizations() {
        requireSuperAdmin();
        return organizationRepository.findByStatus(OrganizationStatus.PENDING)
                .stream().map(this::response).toList();
    }

    @Transactional(readOnly = true)
    public OrganizationRegistryResponse getRegistry() {
        User actor = requireSuperAdmin();
        Organization ownOrganization = actor.getOrganization();
        OrganizationRegistryItem ownItem = ownOrganization != null &&
                ownOrganization.getStatus() == OrganizationStatus.APPROVED
                ? registryItem(ownOrganization, true)
                : null;
        Long ownOrganizationId = ownItem == null ? null : ownOrganization.getId();
        List<OrganizationRegistryItem> approvedOrganizations =
                organizationRepository.findByStatusOrderByNameAsc(OrganizationStatus.APPROVED).stream()
                        .filter(organization -> !organization.getId().equals(ownOrganizationId))
                        .map(organization -> registryItem(organization, false))
                        .toList();
        return new OrganizationRegistryResponse(ownItem, approvedOrganizations);
    }

    @Transactional
    public OrganizationResponse approve(Long orgId) {
        User actor = requireSuperAdmin();
        Organization org = findPendingOrganization(orgId);
        org.setStatus(OrganizationStatus.APPROVED);
        org.setApprovedAt(Instant.now());
        org.setApprovedBy(actor);

        User registrationAdmin = org.getRegistrationAdmin();
        if (registrationAdmin != null &&
                registrationAdmin.getOrganization() != null &&
                registrationAdmin.getOrganization().getId().equals(orgId) &&
                registrationAdmin.getStatus() == UserStatus.PENDING_APPROVAL &&
                registrationAdmin.getRoles().stream().anyMatch(role -> role.getName() == RoleName.ADMIN)) {
            registrationAdmin.setStatus(UserStatus.ACTIVE);
            userRepository.save(registrationAdmin);
        }

        Organization saved = organizationRepository.save(org);
        audit("ORGANIZATION_APPROVED", "Organization registration approved", saved, null, actor);
        return response(saved);
    }

    @Transactional
    public OrganizationResponse reject(Long orgId) {
        User actor = requireSuperAdmin();
        Organization org = findPendingOrganization(orgId);
        org.setStatus(OrganizationStatus.REJECTED);
        org.setApprovedBy(actor);
        User registrationAdmin = org.getRegistrationAdmin();
        if (registrationAdmin != null && registrationAdmin.getOrganization() != null &&
                registrationAdmin.getOrganization().getId().equals(orgId) &&
                registrationAdmin.getStatus() == UserStatus.PENDING_APPROVAL) {
            registrationAdmin.setStatus(UserStatus.DISABLED);
            userRepository.save(registrationAdmin);
        }
        Organization saved = organizationRepository.save(org);
        audit("ORGANIZATION_REJECTED", "Organization registration rejected", saved, null, actor);
        return response(saved);
    }

    @Transactional
    public OrganizationResponse suspend(Long orgId) {
        User actor = requireSuperAdmin();
        Organization org = organizationRepository.findById(orgId)
                .orElseThrow(() -> new IllegalArgumentException("Organization not found"));
        if (org.getStatus() != OrganizationStatus.APPROVED) {
            throw new IllegalStateException("Only approved organizations may be suspended");
        }
        org.setStatus(OrganizationStatus.SUSPENDED);
        org.setApprovedBy(actor);
        Organization saved = organizationRepository.save(org);
        audit("ORGANIZATION_SUSPENDED", "Organization suspended", saved, null, actor);
        return response(saved);
    }

    @Transactional
    public OrganizationDeletionResponse deleteOrganization(Long orgId) {
        User actor = requireSuperAdmin();
        Organization organization = organizationRepository.findByIdForUpdate(orgId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Organization not found"));
        if (actor.getOrganization() != null && actor.getOrganization().getId().equals(orgId)) {
            throw new IllegalStateException("A Super Admin cannot delete their own organization");
        }
        if (organization.getStatus() == OrganizationStatus.DELETED) {
            throw new IllegalStateException("Organization is already deleted");
        }
        if (userRepository.existsActiveSuperAdminInOrganization(orgId)) {
            throw new IllegalStateException("Organization contains an active Super Admin account");
        }

        organization.setStatus(OrganizationStatus.DELETED);
        Organization saved = organizationRepository.save(organization);
        audit("ORGANIZATION_DELETED", "Organization soft-deleted", saved, null, actor);
        return new OrganizationDeletionResponse(saved.getId(), saved.getName(),
                saved.getStatus(), saved.getUpdatedAt());
    }

    @Transactional(readOnly = true)
    public List<MembershipResponse> getPendingMemberships(Long organizationId) {
        requireOrganizationAdmin(organizationId);
        return userRepository.findAnalystMemberships(organizationId, UserStatus.PENDING_APPROVAL)
                .stream().map(this::membershipResponse).toList();
    }

    @Transactional
    public MembershipResponse decideMembership(Long organizationId, Long userId, boolean accept) {
        User actor = requireOrganizationAdmin(organizationId);
        User applicant = userRepository.findByIdAndOrganization_IdForUpdate(userId, organizationId)
                .filter(user -> user.getStatus() == UserStatus.PENDING_APPROVAL)
                .filter(this::isEligibleOrganizationMember)
                .orElseThrow(() -> new IllegalArgumentException("Membership request not found"));
        if (actor.getId().equals(applicant.getId())) {
            log.warn("Denied self-approval attempt by userId={} for organizationId={}", actor.getId(), organizationId);
            throw new AccessDeniedException("Users cannot decide their own membership request");
        }
        applicant.setStatus(accept ? UserStatus.ACTIVE : UserStatus.DISABLED);
        userRepository.save(applicant);
        audit(accept ? "ANALYST_MEMBERSHIP_APPROVED" : "ANALYST_MEMBERSHIP_REJECTED",
                accept ? "Analyst membership approved" : "Analyst membership rejected",
                applicant.getOrganization(), applicant, actor);
        return membershipResponse(applicant);
    }

    @Transactional(readOnly = true)
    public List<MembershipResponse> getMembers(Long organizationId) {
        requireOrganizationAdmin(organizationId);
        return userRepository.findAnalystMemberships(organizationId, UserStatus.ACTIVE)
                .stream().map(this::membershipResponse).toList();
    }

    @Transactional(readOnly = true)
    public OrganizationDashboardResponse getDashboard() {
        Organization organization = requireOrganizationAdmin();
        Long organizationId = organization.getId();
        return new OrganizationDashboardResponse(
                userRepository.countByOrganization_Id(organizationId),
                userRepository.countByOrganization_IdAndStatus(organizationId, UserStatus.ACTIVE),
                userRepository.countByOrganizationAndStatusAndRole(
                        organizationId, UserStatus.PENDING_APPROVAL, RoleName.SECURITY_ANALYST),
                userRepository.countByOrganization_IdAndStatus(organizationId, UserStatus.SUSPENDED),
                userRepository.countByOrganizationAndStatusAndRole(
                        organizationId, UserStatus.ACTIVE, RoleName.SECURITY_ANALYST),
                targetRepository.countByOrganization_Id(organizationId),
                targetRepository.countByOrganization_IdAndStatus(organizationId, TargetStatus.APPROVED),
                scanJobRepository.countByOrganization_IdAndStatus(organizationId, ScanStatus.PENDING_APPROVAL),
                scanJobRepository.countByOrganization_IdAndStatus(organizationId, ScanStatus.QUEUED),
                scanJobRepository.countByOrganization_IdAndStatus(organizationId, ScanStatus.CRAWLING),
                scanJobRepository.countByOrganization_IdAndStatus(organizationId, ScanStatus.SCANNING),
                scanJobRepository.countByOrganization_IdAndStatus(organizationId, ScanStatus.RUNNING),
                scanJobRepository.countByOrganization_IdAndStatus(organizationId, ScanStatus.COMPLETED),
                scanJobRepository.countByOrganization_IdAndStatus(organizationId, ScanStatus.FAILED),
                scanJobRepository.countByOrganization_IdAndStatus(organizationId, ScanStatus.CANCELLED),
                scanJobRepository.countByOrganization_IdAndStatus(organizationId, ScanStatus.REJECTED),
                scanFindingRepository.countByOrganizationAndSeverity(organizationId, "HIGH"),
                scanFindingRepository.countByOrganizationAndSeverity(organizationId, "MEDIUM"),
                scanFindingRepository.countByOrganizationAndSeverity(organizationId, "LOW"));
    }

    @Transactional(readOnly = true)
    public PlatformDashboardResponse getPlatformDashboard() {
        requireSuperAdmin();
        return new PlatformDashboardResponse(
                organizationRepository.count(),
                organizationRepository.countByStatus(OrganizationStatus.PENDING),
                organizationRepository.countByStatus(OrganizationStatus.APPROVED),
                organizationRepository.countByStatus(OrganizationStatus.REJECTED),
                organizationRepository.countByStatus(OrganizationStatus.SUSPENDED));
    }

    @Transactional(readOnly = true)
    public Page<OrganizationUserResponse> getOrganizationUsers(String role, UserStatus status,
                                                                String search, Pageable pageable) {
        Organization organization = requireOrganizationAdmin();
        if (role != null && !role.isBlank() &&
                !RoleName.SECURITY_ANALYST.name().equalsIgnoreCase(role.trim())) {
            throw new IllegalArgumentException("Organization Admins can manage Security Analysts only");
        }
        validatePageable(pageable);
        String normalizedSearch = search == null || search.isBlank() ? null : search.trim();
        return userRepository.searchOrganizationUsers(organization.getId(), status, normalizedSearch, pageable)
                .map(this::organizationUserResponse);
    }

    @Transactional(readOnly = true)
    public OrganizationUserResponse getOrganizationUser(Long userId) {
        Organization organization = requireOrganizationAdmin();
        User user = userRepository.findByIdAndOrganization_Id(userId, organization.getId())
                .filter(this::isEligibleOrganizationMember)
                .orElseThrow(() -> {
                    log.warn("Denied or missing organization user access actorOrgId={} targetUserId={}",
                            organization.getId(), userId);
                    return new IllegalArgumentException("User not found");
                });
        return organizationUserResponse(user);
    }

    @Transactional(readOnly = true)
    public Page<MembershipResponse> getApprovalRequests(Pageable pageable) {
        Organization organization = requireOrganizationAdmin();
        validatePageable(pageable);
        return userRepository.findEligibleApprovalRequests(
                        organization.getId(), UserStatus.PENDING_APPROVAL, pageable)
                .map(this::membershipResponse);
    }

    @Transactional
    public MembershipResponse decideOrganizationApproval(Long userId, boolean accept) {
        Organization organization = requireOrganizationAdmin();
        User actor = currentUser();
        User applicant = userRepository.findByIdAndOrganization_IdForUpdate(userId, organization.getId())
                .filter(user -> user.getStatus() == UserStatus.PENDING_APPROVAL)
                .filter(this::isEligibleOrganizationMember)
                .orElseThrow(() -> {
                    log.warn("Denied or missing approval request actorId={} organizationId={} targetUserId={}",
                            actor.getId(), organization.getId(), userId);
                    return new IllegalArgumentException("Approval request not found");
                });
        if (actor.getId().equals(applicant.getId())) {
            log.warn("Denied self-approval attempt by userId={} for organizationId={}",
                    actor.getId(), organization.getId());
            throw new AccessDeniedException("Users cannot decide their own approval request");
        }
        applicant.setStatus(accept ? UserStatus.ACTIVE : UserStatus.DISABLED);
        userRepository.save(applicant);
        String eventType = accept ? "ORGANIZATION_USER_APPROVED" : "ORGANIZATION_USER_REJECTED";
        audit(eventType, accept ? "Organization user approved" : "Organization user rejected",
                organization, applicant, actor);
        return membershipResponse(applicant);
    }

    @Transactional
    public OrganizationUserResponse suspendOrganizationUser(Long userId) {
        Organization organization = requireOrganizationAdmin();
        organization = lockOrganization(organization.getId());
        User actor = currentUser();
        User target = findEligibleOrganizationUserForUpdate(organization, userId, actor);
        requireManageableStatus(target, UserStatus.ACTIVE);
        target.setStatus(UserStatus.SUSPENDED);
        userRepository.save(target);
        audit("USER_SUSPENDED", "Organization user suspended", organization, target, actor);
        return organizationUserResponse(target);
    }

    @Transactional
    public OrganizationUserResponse restoreOrganizationUser(Long userId) {
        Organization organization = requireOrganizationAdmin();
        organization = lockOrganization(organization.getId());
        User actor = currentUser();
        User target = findEligibleOrganizationUserForUpdate(organization, userId, actor);
        requireManageableStatus(target, UserStatus.SUSPENDED);
        target.setStatus(UserStatus.ACTIVE);
        userRepository.save(target);
        audit("USER_RESTORED", "Organization user restored", organization, target, actor);
        return organizationUserResponse(target);
    }

    @Transactional
    public OrganizationUserResponse deactivateOrganizationUser(Long userId) {
        Organization organization = requireOrganizationAdmin();
        organization = lockOrganization(organization.getId());
        User actor = currentUser();
        User target = findEligibleOrganizationUserForUpdate(organization, userId, actor);
        if (target.getStatus() != UserStatus.ACTIVE && target.getStatus() != UserStatus.SUSPENDED) {
            throw new IllegalStateException("Only active or suspended users may be deactivated");
        }
        target.setStatus(UserStatus.DISABLED);
        userRepository.save(target);
        audit("USER_DEACTIVATED", "Organization user deactivated", organization, target, actor);
        return organizationUserResponse(target);
    }

    @Transactional(readOnly = true)
    public Page<OrganizationUserResponse> getOrganizationAdmins(UserStatus status, Pageable pageable) {
        requireSuperAdmin();
        validatePageable(pageable);
        return userRepository.findOrganizationAdmins(status, pageable).map(this::organizationUserResponse);
    }

    @Transactional
    public OrganizationUserResponse suspendOrganizationAdmin(Long userId) {
        return updateOrganizationAdmin(userId, UserStatus.SUSPENDED, "ADMIN_SUSPENDED",
                "Organization administrator suspended");
    }

    @Transactional
    public OrganizationUserResponse restoreOrganizationAdmin(Long userId) {
        return updateOrganizationAdmin(userId, UserStatus.ACTIVE, "ADMIN_RESTORED",
                "Organization administrator restored");
    }

    @Transactional
    public OrganizationUserResponse deactivateOrganizationAdmin(Long userId) {
        return updateOrganizationAdmin(userId, UserStatus.DISABLED, "ADMIN_DEACTIVATED",
                "Organization administrator deactivated");
    }

    private Organization findPendingOrganization(Long orgId) {
        Organization org = organizationRepository.findByIdForUpdate(orgId)
                .orElseThrow(() -> new IllegalArgumentException("Organization registration not found"));
        if (org.getStatus() != OrganizationStatus.PENDING) {
            throw new IllegalStateException("Organization registration is no longer pending");
        }
        return org;
    }

    private User requireSuperAdmin() {
        User actor = currentUser();
        if (actor.getStatus() != UserStatus.ACTIVE ||
                actor.getRoles().stream().noneMatch(role -> role.getName() == RoleName.SUPER_ADMIN)) {
            throw new AccessDeniedException("Platform approval permission required");
        }
        return actor;
    }

    private User requireOrganizationAdmin(Long organizationId) {
        User actor = currentUser();
        boolean isAdmin = actor.getRoles().stream().anyMatch(role -> role.getName() == RoleName.ADMIN);
        if (actor.getStatus() != UserStatus.ACTIVE || !isAdmin || actor.getOrganization() == null ||
                !organizationId.equals(actor.getOrganization().getId())) {
            log.warn("Denied organization admin operation actorId={} requestedOrganizationId={}",
                    actor.getId(), organizationId);
            throw new AccessDeniedException("Organization membership required");
        }
        organizationRepository.findById(organizationId)
                .filter(org -> org.getStatus() == OrganizationStatus.APPROVED)
                .orElseThrow(() -> new AccessDeniedException("Organization membership required"));
        return actor;
    }

    private Organization requireOrganizationAdmin() {
        User actor = currentUser();
        boolean isAdmin = actor.getRoles().stream().anyMatch(role -> role.getName() == RoleName.ADMIN);
        if (actor.getStatus() != UserStatus.ACTIVE || !isAdmin || actor.getOrganization() == null) {
            log.warn("Denied organization admin operation actorId={}", actor.getId());
            throw new AccessDeniedException("Organization membership required");
        }
        return organizationRepository.findById(actor.getOrganization().getId())
                .filter(org -> org.getStatus() == OrganizationStatus.APPROVED)
                .orElseThrow(() -> new AccessDeniedException("Organization membership required"));
    }

    private Organization lockOrganization(Long organizationId) {
        return organizationRepository.findByIdForUpdate(organizationId)
                .filter(org -> org.getStatus() == OrganizationStatus.APPROVED)
                .orElseThrow(() -> new AccessDeniedException("Organization membership required"));
    }

    private User findEligibleOrganizationUserForUpdate(Organization organization, Long userId, User actor) {
        User target = userRepository.findByIdAndOrganization_IdForUpdate(userId, organization.getId())
                .filter(this::isEligibleOrganizationMember)
                .orElseThrow(() -> {
                    log.warn("Denied or missing organization user management actorId={} organizationId={} targetUserId={}",
                            actor.getId(), organization.getId(), userId);
                    return new IllegalArgumentException("User not found");
                });
        if (actor.getId().equals(target.getId())) {
            log.warn("Denied self-management attempt by userId={} for organizationId={}",
                    actor.getId(), organization.getId());
            throw new AccessDeniedException("Users cannot manage their own account");
        }
        return target;
    }

    private boolean isEligibleOrganizationMember(User user) {
        return user.getRoles().size() == 1 && user.getRoles().stream()
                .anyMatch(role -> role.getName() == RoleName.SECURITY_ANALYST);
    }

    private void requireManageableStatus(User target, UserStatus expectedStatus) {
        if (target.getStatus() != expectedStatus) {
            throw new IllegalStateException("User account is not in the required state");
        }
    }

    private OrganizationUserResponse updateOrganizationAdmin(Long userId, UserStatus nextStatus,
                                                               String eventType, String message) {
        User actor = requireSuperAdmin();
        User target = userRepository.findByIdForUpdate(userId)
                .filter(user -> user.getStatus() != UserStatus.PENDING_APPROVAL)
                .filter(user -> user.getOrganization() != null)
                .filter(user -> user.getRoles().size() == 1 &&
                        user.getRoles().stream().anyMatch(role -> role.getName() == RoleName.ADMIN))
                .orElseThrow(() -> new IllegalArgumentException("Organization administrator not found"));
        if (actor.getId().equals(target.getId())) {
            log.warn("Denied Super Admin self-management attempt actorId={} targetUserId={}", actor.getId(), userId);
            throw new AccessDeniedException("Super Admin cannot manage their own account through this endpoint");
        }

        Organization organization = lockOrganization(target.getOrganization().getId());
        if (organization.getStatus() != OrganizationStatus.APPROVED) {
            throw new IllegalStateException("Organization is not approved");
        }
        UserStatus currentStatus = target.getStatus();
        if ((nextStatus == UserStatus.SUSPENDED && currentStatus != UserStatus.ACTIVE) ||
                (nextStatus == UserStatus.ACTIVE && currentStatus != UserStatus.SUSPENDED) ||
                (nextStatus == UserStatus.DISABLED && currentStatus != UserStatus.ACTIVE &&
                        currentStatus != UserStatus.SUSPENDED)) {
            throw new IllegalStateException("Organization administrator account is not in the required state");
        }
        if (nextStatus != UserStatus.ACTIVE && currentStatus == UserStatus.ACTIVE &&
                userRepository.countOrganizationAdminsByStatus(organization.getId(), UserStatus.ACTIVE) <= 1) {
            throw new IllegalStateException("The last active organization administrator cannot be removed");
        }
        target.setStatus(nextStatus);
        userRepository.save(target);
        audit(eventType, message, organization, target, actor);
        return organizationUserResponse(target);
    }

    private void validatePageable(Pageable pageable) {
        if (pageable.getPageSize() > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("Page size cannot exceed " + MAX_PAGE_SIZE);
        }
        if (pageable.getSort().stream().anyMatch(order ->
                !List.of("createdAt", "firstName", "lastName", "status").contains(order.getProperty()))) {
            throw new IllegalArgumentException("Unsupported sort field");
        }
    }

    private User currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null ||
                !authentication.isAuthenticated()) {
            throw new AccessDeniedException("Authentication required");
        }
        return userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new AccessDeniedException("Authentication required"));
    }

    private OrganizationResponse response(Organization org) {
        User proposedAdmin = org.getRegistrationAdmin();
        return new OrganizationResponse(
                org.getId(), org.getName(), org.getStatus(), org.getContactEmail(),
                org.getPrimaryContactName(), org.getCreatedAt(), org.getUpdatedAt(),
                proposedAdmin == null ? null : proposedAdmin.getEmail(),
                proposedAdmin == null ? null : proposedAdmin.getFirstName(),
                proposedAdmin == null ? null : proposedAdmin.getLastName());
    }

    private OrganizationRegistryItem registryItem(Organization organization, boolean ownOrganization) {
        User registrationAdmin = organization.getRegistrationAdmin();
        return new OrganizationRegistryItem(organization.getId(), organization.getName(),
                organization.getStatus(), ownOrganization, organization.getCreatedAt(),
                organization.getApprovedAt(), registrationAdmin == null ? null : displayName(registrationAdmin));
    }

    private MembershipResponse membershipResponse(User user) {
        return new MembershipResponse(user.getId(), displayName(user),
                user.getRoles().stream().map(role -> role.getName().name()).sorted().toList(),
                user.getStatus(), user.getCreatedAt());
    }

    private OrganizationUserResponse organizationUserResponse(User user) {
        return new OrganizationUserResponse(user.getId(), displayName(user),
                user.getRoles().stream().map(role -> role.getName().name()).sorted().toList(),
                user.getStatus(), user.getCreatedAt());
    }

    private String displayName(User user) {
        String name = ((user.getFirstName() == null ? "" : user.getFirstName()) + " " +
                (user.getLastName() == null ? "" : user.getLastName())).trim();
        return name.isEmpty() ? null : name;
    }

    private void audit(String type, String message, Organization organization, User target, User actor) {
        AuditEvent event = new AuditEvent();
        event.setEventType(type);
        event.setEventLevel("INFO");
        event.setMessage(message);
        event.setOrganization(organization);
        event.setActor(actor);
        event.setTargetUser(target);
        auditEventRepository.save(event);
    }
}
