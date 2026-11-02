package com.vulnscanner.application.target;

import com.vulnscanner.application.common.ApiResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/targets")
public class TargetController {
    private final TargetService targetService;

    public TargetController(TargetService targetService) {
        this.targetService = targetService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<ApiResponse<List<TargetResponse>>> listTargets() {
        return ResponseEntity.ok(ApiResponse.success("Targets retrieved", targetService.listTargets()));
    }

    @GetMapping("/{targetId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<ApiResponse<TargetResponse>> getTarget(@PathVariable Long targetId) {
        return ResponseEntity.ok(ApiResponse.success("Target retrieved", targetService.getTarget(targetId)));
    }

    @GetMapping("/assignment-analysts")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<AnalystAssignmentCandidateResponse>>> eligibleAnalysts() {
        return ResponseEntity.ok(ApiResponse.success(
                "Eligible Security Analysts retrieved", targetService.eligibleAnalysts()));
    }

    @GetMapping("/{targetId}/assignments")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<TargetAnalystAssignmentResponse>>> assignments(
            @PathVariable Long targetId) {
        return ResponseEntity.ok(ApiResponse.success(
                "Target assignments retrieved", targetService.assignments(targetId)));
    }

    @PutMapping("/{targetId}/assignments/{analystId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<TargetAnalystAssignmentResponse>> assignAnalyst(
            @PathVariable Long targetId, @PathVariable Long analystId) {
        return ResponseEntity.ok(ApiResponse.success(
                "Security Analyst assigned to target", targetService.assignAnalyst(targetId, analystId)));
    }

    @DeleteMapping("/{targetId}/assignments/{analystId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> revokeAnalystAssignment(
            @PathVariable Long targetId, @PathVariable Long analystId) {
        targetService.revokeAnalystAssignment(targetId, analystId);
        return ResponseEntity.ok(ApiResponse.success("Target assignment revoked", null));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<TargetResponse>> createTarget(
            @Valid @RequestBody TargetCreateRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Target created", targetService.createTarget(request)));
    }

    @PostMapping("/{targetId}/decision")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<TargetResponse>> decideTarget(
            @PathVariable Long targetId, @Valid @RequestBody TargetDecisionRequest request) {
        return ResponseEntity.ok(ApiResponse.success("Target decision recorded",
                targetService.decideTarget(targetId, request)));
    }

    @DeleteMapping("/{targetId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<TargetResponse>> deleteTarget(@PathVariable Long targetId) {
        return ResponseEntity.ok(ApiResponse.success("Target deactivated",
                targetService.deleteTarget(targetId)));
    }
}
