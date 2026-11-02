package com.vulnscanner.application.scan;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.List;
import java.time.Instant;

public interface ScanJobRepository extends JpaRepository<ScanJob, Long> {
    Page<ScanJob> findByOrganization_IdOrderByCreatedAtDesc(Long organizationId, Pageable pageable);

    Optional<ScanJob> findByIdAndOrganization_Id(Long id, Long organizationId);

    Optional<ScanJob> findByIdAndRequestedBy_Id(Long id, Long requestedById);

    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.EntityGraph(attributePaths = {
            "target", "target.organization", "organization", "requestedBy",
            "requestedBy.organization", "requestedBy.roles", "reviewedBy"
    })
    @org.springframework.data.jpa.repository.Query("SELECT s FROM ScanJob s WHERE s.id = :id")
    Optional<ScanJob> findByIdForExecutionUpdate(
            @org.springframework.data.repository.query.Param("id") Long id);

    @org.springframework.data.jpa.repository.Query("SELECT s.cancellationRequested FROM ScanJob s WHERE s.id = :id")
    Optional<Boolean> findCancellationRequestedById(
            @org.springframework.data.repository.query.Param("id") Long id);

    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("""
            SELECT s FROM ScanJob s
            WHERE s.id = :id AND s.organization.id = :organizationId
            """)
    Optional<ScanJob> findByIdAndOrganizationForUpdate(
            @org.springframework.data.repository.query.Param("id") Long id,
            @org.springframework.data.repository.query.Param("organizationId") Long organizationId);

    Page<ScanJob> findByOrganization_IdAndStatusOrderByCreatedAtAsc(
            Long organizationId, ScanStatus status, Pageable pageable);

    Page<ScanJob> findByTarget_IdInAndOrganization_IdOrderByCreatedAtDesc(
            List<Long> targetIds, Long organizationId, Pageable pageable);

    Page<ScanJob> findByTarget_IdAndOrganization_IdAndScanTypeOrderByCreatedAtDesc(
            Long targetId, Long organizationId, ScanType scanType, Pageable pageable);

    long countByTarget_IdInAndOrganization_IdAndStatus(
            List<Long> targetIds, Long organizationId, ScanStatus status);

    long countByRequestedBy_IdAndTarget_IdInAndOrganization_IdAndStatus(
            Long requestedById, List<Long> targetIds, Long organizationId, ScanStatus status);

    long countByOrganization_IdAndStatus(Long organizationId, ScanStatus status);

    long countByRequestedBy_IdAndStatus(Long userId, ScanStatus status);

    @org.springframework.data.jpa.repository.Query("""
            SELECT FUNCTION('DATE', s.createdAt), s.status, COUNT(s)
            FROM ScanJob s
            WHERE s.organization.id = :organizationId
              AND s.createdAt >= :start AND s.createdAt < :end
            GROUP BY FUNCTION('DATE', s.createdAt), s.status
            """)
    List<Object[]> countDailyByOrganization(
            @org.springframework.data.repository.query.Param("organizationId") Long organizationId,
            @org.springframework.data.repository.query.Param("start") Instant start,
            @org.springframework.data.repository.query.Param("end") Instant end);

    @org.springframework.data.jpa.repository.Query("""
            SELECT FUNCTION('DATE', s.createdAt), s.status, COUNT(s)
            FROM ScanJob s
            WHERE s.organization.id = :organizationId AND s.target.id IN :targetIds
              AND s.createdAt >= :start AND s.createdAt < :end
            GROUP BY FUNCTION('DATE', s.createdAt), s.status
            """)
    List<Object[]> countDailyByAssignedTargets(
            @org.springframework.data.repository.query.Param("organizationId") Long organizationId,
            @org.springframework.data.repository.query.Param("targetIds") List<Long> targetIds,
            @org.springframework.data.repository.query.Param("start") Instant start,
            @org.springframework.data.repository.query.Param("end") Instant end);

    List<ScanJob> findByStatusIn(java.util.Collection<ScanStatus> statuses);
}
