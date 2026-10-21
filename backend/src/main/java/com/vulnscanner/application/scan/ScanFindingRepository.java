package com.vulnscanner.application.scan;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
public interface ScanFindingRepository extends JpaRepository<ScanFinding, Long> {
    List<ScanFinding> findByScanJob_Id(Long scanJobId);

    List<ScanFinding> findByScanJob_IdAndScanJob_Organization_IdOrderByDetectedAtDesc(
            Long scanJobId, Long organizationId);

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
}
