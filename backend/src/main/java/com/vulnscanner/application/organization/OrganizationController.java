package com.vulnscanner.application.organization;

import com.vulnscanner.application.common.ApiResponse;
import com.vulnscanner.application.user.UserStatus;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/organizations")
public class OrganizationController {
    private final OrganizationService organizationService;

    public OrganizationController(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @PostMapping("/register")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> register(@Valid @RequestBody OrganizationRegistrationRequest request) {
        Organization org = organizationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Organization registration submitted",
                        Map.of("id", org.getId(), "status", org.getStatus())));
    }

    @GetMapping("/pending")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<List<OrganizationResponse>>> getPendingOrganizations() {
        return ResponseEntity.ok(ApiResponse.success("Pending organizations retrieved",
                organizationService.getPendingOrganizations()));
    }

    @GetMapping("/registry")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationRegistryResponse>> getRegistry() {
        return ResponseEntity.ok(ApiResponse.success("Organization registry retrieved",
                organizationService.getRegistry()));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationResponse>> getOrganization(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success("Organization registration metadata retrieved",
                organizationService.getOrganizationForAdmin(id)));
    }

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationResponse>> approve(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success("Organization approved",
                organizationService.approve(id)));
    }

    @PostMapping("/{id}/reject")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationResponse>> reject(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success("Organization rejected",
                organizationService.reject(id)));
    }

    @PostMapping("/{id}/suspend")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationResponse>> suspend(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success("Organization suspended",
                organizationService.suspend(id)));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationDeletionResponse>> deleteOrganization(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.success("Organization soft-deleted",
                organizationService.deleteOrganization(id)));
    }

    @GetMapping("/{organizationId}/membership-requests")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<MembershipResponse>>> getPendingMemberships(
            @PathVariable Long organizationId) {
        return ResponseEntity.ok(ApiResponse.success("Pending membership requests retrieved",
                organizationService.getPendingMemberships(organizationId)));
    }

    @PostMapping("/{organizationId}/membership-requests/{userId}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<MembershipResponse>> approveMembership(
            @PathVariable Long organizationId, @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Membership approved",
                organizationService.decideMembership(organizationId, userId, true)));
    }

    @PostMapping("/{organizationId}/membership-requests/{userId}/reject")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<MembershipResponse>> rejectMembership(
            @PathVariable Long organizationId, @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Membership rejected",
                organizationService.decideMembership(organizationId, userId, false)));
    }

    @GetMapping("/{organizationId}/members")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<MembershipResponse>>> getMembers(
            @PathVariable Long organizationId) {
        return ResponseEntity.ok(ApiResponse.success("Organization members retrieved",
                organizationService.getMembers(organizationId)));
    }

    @GetMapping("/me/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationDashboardResponse>> getDashboard() {
        return ResponseEntity.ok(ApiResponse.success("Organization dashboard retrieved",
                organizationService.getDashboard()));
    }

    @GetMapping("/platform-dashboard")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<PlatformDashboardResponse>> getPlatformDashboard() {
        return ResponseEntity.ok(ApiResponse.success("Platform dashboard retrieved",
                organizationService.getPlatformDashboard()));
    }

    @GetMapping("/me/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Page<OrganizationUserResponse>>> getOrganizationUsers(
            @RequestParam(required = false) String role,
            @RequestParam(required = false) UserStatus status,
            @RequestParam(required = false) String search,
            @PageableDefault(size = 20, sort = "createdAt") Pageable pageable) {
        return ResponseEntity.ok(ApiResponse.success("Organization users retrieved",
                organizationService.getOrganizationUsers(role, status, search, pageable)));
    }

    @GetMapping("/me/users/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationUserResponse>> getOrganizationUser(
            @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Organization user retrieved",
                organizationService.getOrganizationUser(userId)));
    }

    @GetMapping("/me/approval-requests")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Page<MembershipResponse>>> getApprovalRequests(
            @PageableDefault(size = 20, sort = "createdAt") Pageable pageable) {
        return ResponseEntity.ok(ApiResponse.success("Pending approval requests retrieved",
                organizationService.getApprovalRequests(pageable)));
    }

    @PostMapping("/me/approval-requests/{userId}/approve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<MembershipResponse>> approveOrganizationUser(
            @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Organization user approved",
                organizationService.decideOrganizationApproval(userId, true)));
    }

    @PostMapping("/me/approval-requests/{userId}/reject")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<MembershipResponse>> rejectOrganizationUser(
            @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Organization user rejected",
                organizationService.decideOrganizationApproval(userId, false)));
    }

    @PostMapping("/me/users/{userId}/suspend")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationUserResponse>> suspendOrganizationUser(
            @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Organization user suspended",
                organizationService.suspendOrganizationUser(userId)));
    }

    @PostMapping("/me/users/{userId}/restore")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationUserResponse>> restoreOrganizationUser(
            @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Organization user restored",
                organizationService.restoreOrganizationUser(userId)));
    }

    @PostMapping("/me/users/{userId}/deactivate")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationUserResponse>> deactivateOrganizationUser(
            @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Organization user deactivated",
                organizationService.deactivateOrganizationUser(userId)));
    }

    @GetMapping("/admin-accounts")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Page<OrganizationUserResponse>>> getOrganizationAdmins(
            @RequestParam(required = false) UserStatus status,
            @PageableDefault(size = 20, sort = "createdAt") Pageable pageable) {
        return ResponseEntity.ok(ApiResponse.success("Organization administrator accounts retrieved",
                organizationService.getOrganizationAdmins(status, pageable)));
    }

    @PostMapping("/admin-accounts/{userId}/suspend")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationUserResponse>> suspendOrganizationAdmin(
            @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Organization administrator suspended",
                organizationService.suspendOrganizationAdmin(userId)));
    }

    @PostMapping("/admin-accounts/{userId}/restore")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationUserResponse>> restoreOrganizationAdmin(
            @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Organization administrator restored",
                organizationService.restoreOrganizationAdmin(userId)));
    }

    @PostMapping("/admin-accounts/{userId}/deactivate")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<OrganizationUserResponse>> deactivateOrganizationAdmin(
            @PathVariable Long userId) {
        return ResponseEntity.ok(ApiResponse.success("Organization administrator deactivated",
                organizationService.deactivateOrganizationAdmin(userId)));
    }
}
