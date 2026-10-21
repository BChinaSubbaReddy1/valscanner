package com.vulnscanner.application.target;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TargetRepository extends JpaRepository<Target, Long> {
    List<Target> findByOrganization_IdAndStatusNotOrderByCreatedAtDesc(Long organizationId, TargetStatus status);

    List<Target> findByOrganization_IdAndStatusOrderByCreatedAtDesc(Long organizationId, TargetStatus status);

    Optional<Target> findByIdAndOrganization_IdAndStatusNot(Long id, Long organizationId, TargetStatus status);

    Optional<Target> findByIdAndOrganization_IdAndStatus(Long id, Long organizationId, TargetStatus status);

    long countByOrganization_Id(Long organizationId);

    long countByOrganization_IdAndStatus(Long organizationId, TargetStatus status);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT t FROM Target t WHERE t.id = :id AND t.organization.id = :organizationId")
    Optional<Target> findByIdAndOrganizationIdForUpdate(
            @Param("id") Long id, @Param("organizationId") Long organizationId);
}
