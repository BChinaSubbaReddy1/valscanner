package com.vulnscanner.application.auth;

import com.vulnscanner.application.audit.AuditEvent;
import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.security.JwtService;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;
import java.util.Set;

@Service
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final OrganizationRepository organizationRepository;
    private final AuditEventRepository auditEventRepository;
    private final JwtService jwtService;

    public AuthService(AuthenticationManager authenticationManager,
                       UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       RoleRepository roleRepository,
                       OrganizationRepository organizationRepository,
                       AuditEventRepository auditEventRepository,
                       JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.organizationRepository = organizationRepository;
        this.auditEventRepository = auditEventRepository;
        this.jwtService = jwtService;
    }

    public void logout(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwtService.invalidateToken(authHeader.substring(7));
        }
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.password()));
        User user = userRepository.findByEmail(email).orElseThrow();
        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.LOCKED) {
            throw new IllegalStateException("Account is not active");
        }
        if (user.getOrganization() != null && user.getOrganization().getStatus() != OrganizationStatus.APPROVED) {
            throw new IllegalStateException("Organization is not approved");
        }
        String token = jwtService.generateToken(user);
        return new LoginResponse(token, "Bearer", user.getId(), user.getEmail(),
                user.getRoles().stream()
                        .filter(role -> role.getName() != RoleName.CUSTOMER)
                        .map(role -> role.getName().name()).toList());
    }

    @Transactional
    public User register(RegisterRequest request) {
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already registered");
        }
        RoleName requestedRole;
        try {
            requestedRole = request.role() == null || request.role().isBlank()
                    ? RoleName.SECURITY_ANALYST
                    : RoleName.valueOf(request.role().trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException invalidRole) {
            throw new IllegalArgumentException("Unsupported registration role");
        }
        if (requestedRole != RoleName.ADMIN && requestedRole != RoleName.SECURITY_ANALYST) {
            throw new IllegalArgumentException("Public registration cannot assign this role");
        }

        User user = new User();
        user.setFirstName(request.firstName().trim());
        user.setLastName(request.lastName().trim());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setStatus(UserStatus.PENDING_APPROVAL);
        user.setRoles(Set.of(roleRepository.findByName(requestedRole)
                .orElseThrow(() -> new IllegalStateException(requestedRole + " role missing"))));

        Organization organization;
        if (requestedRole == RoleName.ADMIN) {
            if (request.organizationName() == null || request.organizationName().isBlank()) {
                throw new IllegalArgumentException("Organization Admin registration requires an organization name");
            }
            if (!organizationRepository.findAllByNormalizedName(request.organizationName().trim()).isEmpty()) {
                throw new IllegalArgumentException("Organization already exists");
            }
            organization = new Organization();
            organization.setName(request.organizationName().trim());
            organization.setContactEmail(request.organizationContactEmail() == null ||
                    request.organizationContactEmail().isBlank() ? email :
                    request.organizationContactEmail().trim().toLowerCase(Locale.ROOT));
            organization.setPrimaryContactName(user.getFirstName() + " " + user.getLastName());
            organization.setStatus(OrganizationStatus.PENDING);
            organization = organizationRepository.save(organization);
        } else {
            if (request.organizationName() == null || request.organizationName().isBlank() ||
                    request.organizationContactEmail() != null) {
                throw new IllegalArgumentException("Security Analyst registration requires an organization name");
            }
            var matchingOrganizations = organizationRepository.findAllByNormalizedName(
                    request.organizationName().trim());
            if (matchingOrganizations.isEmpty()) {
                throw new IllegalArgumentException("No organization matches the supplied name");
            }
            if (matchingOrganizations.size() > 1) {
                throw new IllegalArgumentException("Organization name is ambiguous; contact support");
            }
            organization = matchingOrganizations.getFirst();
            if (organization.getStatus() != OrganizationStatus.APPROVED) {
                throw new IllegalArgumentException("The requested organization is not approved");
            }
        }
        user.setOrganization(organization);
        User saved = userRepository.save(user);
        if (requestedRole == RoleName.ADMIN) {
            organization.setRegistrationAdmin(saved);
            organizationRepository.save(organization);
        }
        AuditEvent event = new AuditEvent();
        event.setEventType(requestedRole == RoleName.ADMIN
                ? "ORGANIZATION_ADMIN_REGISTRATION_SUBMITTED"
                : "ORGANIZATION_MEMBERSHIP_REQUESTED");
        event.setEventLevel("INFO");
        event.setOrganization(organization);
        event.setTargetUser(saved);
        event.setActor(saved);
        event.setMessage("Pending " + requestedRole + " registration submitted for " + saved.getEmail());
        auditEventRepository.save(event);
        return saved;
    }

    @Transactional
    public void requestPasswordReset(ForgotPasswordRequest request) {
        throw passwordResetUnavailable();
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        throw passwordResetUnavailable();
    }

    private ResponseStatusException passwordResetUnavailable() {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "Password reset delivery is not configured");
    }
}
