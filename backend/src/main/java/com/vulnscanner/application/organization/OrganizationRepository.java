package com.vulnscanner.application.organization;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.List;

public interface OrganizationRepository extends JpaRepository<Organization, Long> {
    @Query("SELECT o FROM Organization o WHERE LOWER(TRIM(o.name)) = LOWER(TRIM(:name))")
    List<Organization> findAllByNormalizedName(@Param("name") String name);

    java.util.List<Organization> findByStatus(OrganizationStatus status);
    java.util.List<Organization> findByStatusOrderByNameAsc(OrganizationStatus status);

    long countByStatus(OrganizationStatus status);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT o FROM Organization o WHERE o.id = :id")
    Optional<Organization> findByIdForUpdate(@Param("id") Long id);
}
