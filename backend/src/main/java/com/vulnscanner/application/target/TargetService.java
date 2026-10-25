package com.vulnscanner.application.target;

import com.vulnscanner.application.audit.AuditEvent;
import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.security.UserPrincipal;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;

@Service
public class TargetService {
    private final TargetRepository targetRepository;
    private final UserRepository userRepository;
    private final AuditEventRepository auditEventRepository;

    public TargetService(TargetRepository targetRepository, UserRepository userRepository,
                         AuditEventRepository auditEventRepository) {
        this.targetRepository = targetRepository;
        this.userRepository = userRepository;
        this.auditEventRepository = auditEventRepository;
    }

    @Transactional(readOnly = true)
    public List<TargetResponse> listTargets() {
        User actor = currentUser();
        Organization organization = requireOrganization(actor);
        if (hasRole(actor, RoleName.ADMIN)) {
            return targetRepository.findByOrganization_IdAndStatusNotOrderByCreatedAtDesc(
                            organization.getId(), TargetStatus.DELETED)
                    .stream().map(this::response).toList();
        }
        requireRole(actor, RoleName.SECURITY_ANALYST);
        return targetRepository.findByOrganization_IdAndStatusOrderByCreatedAtDesc(
                        organization.getId(), TargetStatus.APPROVED)
                .stream().map(this::response).toList();
    }

    @Transactional(readOnly = true)
    public TargetResponse getTarget(Long targetId) {
        User actor = currentUser();
        Organization organization = requireOrganization(actor);
        Target target;
        if (hasRole(actor, RoleName.ADMIN)) {
            target = targetRepository.findByIdAndOrganization_IdAndStatusNot(
                            targetId, organization.getId(), TargetStatus.DELETED)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Target not found"));
        } else {
            requireRole(actor, RoleName.SECURITY_ANALYST);
            target = targetRepository.findByIdAndOrganization_IdAndStatus(
                            targetId, organization.getId(), TargetStatus.APPROVED)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Target not found"));
        }
        return response(target);
    }

    @Transactional
    public TargetResponse createTarget(TargetCreateRequest request) {
        User actor = requireAdmin();
        Organization organization = requireOrganization(actor);
        Target target = new Target();
        target.setName(request.name().trim());
        target.setUrl(validateUrl(request.url()));
        target.setType(request.type());
        target.setOrganization(organization);
        target.setCreatedBy(actor);
        target.setStatus(TargetStatus.PENDING);
        Target saved = targetRepository.save(target);
        audit("TARGET_CREATED", "Target created: " + saved.getId(), organization, actor);
        return response(saved);
    }

    @Transactional
    public TargetResponse decideTarget(Long targetId, TargetDecisionRequest request) {
        User actor = requireAdmin();
        Organization organization = requireOrganization(actor);
        Target target = findForUpdate(targetId, organization);
        if (target.getStatus() != TargetStatus.PENDING) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Only pending targets can be decided");
        }
        target.setStatus(request.decision() == TargetDecision.APPROVE
                ? TargetStatus.APPROVED : TargetStatus.REJECTED);
        target.setDecidedBy(actor);
        Target saved = targetRepository.save(target);
        String event = request.decision() == TargetDecision.APPROVE
                ? "TARGET_APPROVED" : "TARGET_REJECTED";
        audit(event, "Target " + request.decision().name().toLowerCase(Locale.ROOT) + ": " + saved.getId(),
                organization, actor);
        return response(saved);
    }

    @Transactional
    public TargetResponse deleteTarget(Long targetId) {
        User actor = requireAdmin();
        Organization organization = requireOrganization(actor);
        Target target = findForUpdate(targetId, organization);
        if (target.getStatus() == TargetStatus.DELETED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Target is already deleted");
        }
        target.setStatus(TargetStatus.DELETED);
        Target saved = targetRepository.save(target);
        audit("TARGET_DELETED", "Target deactivated: " + saved.getId(), organization, actor);
        return response(saved);
    }

    private Target findForUpdate(Long targetId, Organization organization) {
        return targetRepository.findByIdAndOrganizationIdForUpdate(targetId, organization.getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Target not found"));
    }

    private User requireAdmin() {
        User actor = currentUser();
        requireRole(actor, RoleName.ADMIN);
        return actor;
    }

    private Organization requireOrganization(User actor) {
        Organization organization = actor.getOrganization();
        if (organization == null || organization.getStatus() != OrganizationStatus.APPROVED) {
            throw new AccessDeniedException("An approved organization membership is required");
        }
        return organization;
    }

    private User currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() ||
                authentication.getPrincipal() instanceof String) {
            throw new AccessDeniedException("Authentication required");
        }
        String email = authentication.getName();
        User actor = userRepository.findByEmail(email)
                .orElseThrow(() -> new AccessDeniedException("Authentication required"));
        if (actor.getStatus() != UserStatus.ACTIVE) {
            throw new AccessDeniedException("Active account required");
        }
        return actor;
    }

    private void requireRole(User actor, RoleName role) {
        if (!hasRole(actor, role)) {
            throw new AccessDeniedException("Insufficient role");
        }
    }

    private boolean hasRole(User actor, RoleName role) {
        return actor.getRoles().stream().anyMatch(userRole -> userRole.getName() == role);
    }

    private String validateUrl(String value) {
        try {
            URI uri = new URI(value.trim());
            String scheme = uri.getScheme();
            if (!uri.isAbsolute() || uri.isOpaque() || uri.getRawAuthority() == null
                    || uri.getHost() == null || uri.getHost().isBlank() ||
                    uri.getRawUserInfo() != null || scheme == null ||
                    (uri.getPort() != -1 && (uri.getPort() < 1 || uri.getPort() > 65535)) ||
                    !hasValidRawAuthority(uri) ||
                    !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                throw new IllegalArgumentException("Target URL must be an HTTP or HTTPS URL without credentials");
            }
            return uri.normalize().toASCIIString();
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Target URL is malformed", exception);
        }
    }

    private boolean hasValidRawAuthority(URI uri) {
        String host = uri.getHost();
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        String authorityHost = host.contains(":") ? "[" + host + "]" : host;
        String expected = uri.getPort() == -1 ? authorityHost : authorityHost + ":" + uri.getPort();
        return expected.equalsIgnoreCase(uri.getRawAuthority());
    }

    private TargetResponse response(Target target) {
        return new TargetResponse(target.getId(), target.getName(), target.getUrl(), target.getType(),
                target.getOrganization().getId(), target.getStatus(), target.getCreatedAt(),
                target.getUpdatedAt());
    }

    private void audit(String type, String message, Organization organization, User actor) {
        AuditEvent event = new AuditEvent();
        event.setEventType(type);
        event.setEventLevel("INFO");
        event.setMessage(message);
        event.setOrganization(organization);
        event.setActor(actor);
        auditEventRepository.save(event);
    }
}
