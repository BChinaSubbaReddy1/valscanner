package com.vulnscanner.application.scan;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.time.Instant;
public interface ScanFindingRepository extends JpaRepository<ScanFinding, Long> {
    List<ScanFinding> findByScanJob_Id(Long scanJobId);

    List<ScanFinding> findByScanJob_IdAndScanJob_Organization_IdOrderByDetectedAtDesc(
            Long scanJobId, Long organizationId);

    @org.springframework.data.jpa.repository.Query("""
            SELECT COALESCE(f.endpointUrl, f.affectedComponent), f.severity, f.checkType,
                   f.detectionSource, f.sourceRuleId, f.sourceCweId, f.parameterName,
                   f.httpMethod, f.affectedComponent, f.evidence, f.verificationStatus, COUNT(f)
            FROM ScanFinding f
            WHERE f.scanJob.id = :scanId AND f.scanJob.organization.id = :organizationId
            GROUP BY COALESCE(f.endpointUrl, f.affectedComponent), f.severity, f.checkType,
                     f.detectionSource, f.sourceRuleId, f.sourceCweId, f.parameterName,
                     f.httpMethod, f.affectedComponent, f.evidence, f.verificationStatus
            """)
    List<Object[]> groupAnalyticsByScan(
            @org.springframework.data.repository.query.Param("scanId") Long scanId,
            @org.springframework.data.repository.query.Param("organizationId") Long organizationId);

    @org.springframework.data.jpa.repository.Query("""
            SELECT COUNT(f) FROM ScanFinding f
            WHERE f.scanJob.organization.id = :organizationId AND f.severity = :severity
            """)
    long countByOrganizationAndSeverity(@org.springframework.data.repository.query.Param("organizationId") Long organizationId,
                                        @org.springframework.data.repository.query.Param("severity") String severity);

    @org.springframework.data.jpa.repository.Query("""
            SELECT COUNT(f) FROM ScanFinding f
            WHERE f.scanJob.requestedBy.id = :userId AND f.severity = :severity
            """)
    long countByRequesterAndSeverity(@org.springframework.data.repository.query.Param("userId") Long userId,
                                     @org.springframework.data.repository.query.Param("severity") String severity);

    @org.springframework.data.jpa.repository.Query("""
            SELECT COUNT(f) FROM ScanFinding f
            WHERE f.scanJob.organization.id = :organizationId
              AND f.scanJob.target.id IN :targetIds
              AND f.severity = :severity
            """)
    long countByAssignedTargetsAndSeverity(
            @org.springframework.data.repository.query.Param("organizationId") Long organizationId,
            @org.springframework.data.repository.query.Param("targetIds") List<Long> targetIds,
            @org.springframework.data.repository.query.Param("severity") String severity);

    @org.springframework.data.jpa.repository.Query("""
            SELECT FUNCTION('DATE', f.detectedAt), f.severity, COUNT(f)
            FROM ScanFinding f
            WHERE f.scanJob.organization.id = :organizationId
              AND f.detectedAt >= :start AND f.detectedAt < :end
            GROUP BY FUNCTION('DATE', f.detectedAt), f.severity
            """)
    List<Object[]> countDailySeverityByOrganization(
            @org.springframework.data.repository.query.Param("organizationId") Long organizationId,
            @org.springframework.data.repository.query.Param("start") Instant start,
            @org.springframework.data.repository.query.Param("end") Instant end);

    @org.springframework.data.jpa.repository.Query("""
            SELECT FUNCTION('DATE', f.detectedAt), f.severity, COUNT(f)
            FROM ScanFinding f
            WHERE f.scanJob.organization.id = :organizationId
              AND f.scanJob.target.id IN :targetIds
              AND f.detectedAt >= :start AND f.detectedAt < :end
            GROUP BY FUNCTION('DATE', f.detectedAt), f.severity
            """)
    List<Object[]> countDailySeverityByAssignedTargets(
            @org.springframework.data.repository.query.Param("organizationId") Long organizationId,
            @org.springframework.data.repository.query.Param("targetIds") List<Long> targetIds,
            @org.springframework.data.repository.query.Param("start") Instant start,
            @org.springframework.data.repository.query.Param("end") Instant end);
}
