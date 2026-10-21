package com.vulnscanner.application.user;

import com.vulnscanner.application.common.ApiResponse;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.RoleName;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    @Transactional(readOnly = true)
    public ResponseEntity<ApiResponse<UserProfileResponse>> currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = userRepository.findByEmail(authentication.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authenticated user not found"));
        Organization organization = user.getOrganization();
        boolean analyst = user.getRoles().stream()
                .anyMatch(role -> role.getName() == RoleName.SECURITY_ANALYST);
        String membershipApprovalStatus = analyst
                ? user.getStatus() == UserStatus.ACTIVE ? "APPROVED" : user.getStatus().name()
                : null;
        UserProfileResponse profile = new UserProfileResponse(
                user.getId(),
                user.getEmail(),
                user.getFirstName() == null ? "" : user.getFirstName(),
                user.getLastName() == null ? "" : user.getLastName(),
                organization == null ? null : organization.getId(),
                organization == null ? null : organization.getName(),
                organization == null ? null : organization.getStatus(),
                user.getRoles().stream()
                        .filter(role -> role.getName() != RoleName.CUSTOMER)
                        .map(role -> role.getName().name())
                        .sorted()
                        .toList(),
                user.getStatus(),
                membershipApprovalStatus);
        return ResponseEntity.ok(ApiResponse.success("Current user profile", profile));
    }
}
