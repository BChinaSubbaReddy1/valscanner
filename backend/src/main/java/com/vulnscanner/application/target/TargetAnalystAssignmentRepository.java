package com.vulnscanner.application.target;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TargetAnalystAssignmentRepository extends JpaRepository<TargetAnalystAssignment, Long> {
    @EntityGraph(attributePaths = {"analyst"})
    List<TargetAnalystAssignment> findByTarget_IdAndTarget_Organization_IdOrderByAnalyst_FirstNameAscAnalyst_LastNameAsc(
            Long targetId, Long organizationId);

    Optional<TargetAnalystAssignment> findByTarget_IdAndAnalyst_Id(Long targetId, Long analystId);

    boolean existsByTarget_IdAndAnalyst_Id(Long targetId, Long analystId);

    @Query("""
            SELECT a.target.id FROM TargetAnalystAssignment a
            WHERE a.analyst.id = :analystId
              AND a.target.organization.id = :organizationId
              AND a.target.status = :targetStatus
            """)
    List<Long> findAssignedTargetIds(@Param("analystId") Long analystId,
                                    @Param("organizationId") Long organizationId,
                                    @Param("targetStatus") TargetStatus targetStatus);

    long countByAnalyst_IdAndTarget_Organization_IdAndTarget_Status(
            Long analystId, Long organizationId, TargetStatus targetStatus);
}
