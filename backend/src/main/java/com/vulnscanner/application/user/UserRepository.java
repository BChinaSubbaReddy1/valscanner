package com.vulnscanner.application.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;

import java.util.Optional;
import java.util.List;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    List<User> findByOrganization_IdAndStatus(Long organizationId, UserStatus status);

    @Query("""
            SELECT DISTINCT u FROM User u JOIN u.roles r
            WHERE u.organization.id = :organizationId
              AND u.status = :status
              AND r.name = com.vulnscanner.application.role.RoleName.SECURITY_ANALYST
            """)
    List<User> findAnalystMemberships(@Param("organizationId") Long organizationId,
                                      @Param("status") UserStatus status);

    Optional<User> findByIdAndOrganization_Id(Long id, Long organizationId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT u FROM User u WHERE u.id = :id AND u.organization.id = :organizationId")
    Optional<User> findByIdAndOrganization_IdForUpdate(@Param("id") Long id,
                                                       @Param("organizationId") Long organizationId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT u FROM User u WHERE u.id = :id")
    Optional<User> findByIdForUpdate(@Param("id") Long id);

    long countByOrganization_Id(Long organizationId);
    long countByOrganization_IdAndStatus(Long organizationId, UserStatus status);

    @Query("""
            SELECT COUNT(DISTINCT u) FROM User u JOIN u.roles r
            WHERE u.organization.id = :organizationId
              AND u.status = :status
              AND r.name = :role
            """)
    long countByOrganizationAndStatusAndRole(@Param("organizationId") Long organizationId,
                                             @Param("status") UserStatus status,
                                             @Param("role") com.vulnscanner.application.role.RoleName role);

    @Query(value = """
            SELECT DISTINCT u FROM User u JOIN u.roles r
            WHERE u.organization.id = :organizationId
              AND r.name = com.vulnscanner.application.role.RoleName.SECURITY_ANALYST
              AND (:status IS NULL OR u.status = :status)
              AND (:search IS NULL OR LOWER(CONCAT(COALESCE(u.firstName, ''), ' ',
                  COALESCE(u.lastName, ''))) LIKE LOWER(CONCAT('%', :search, '%')))
            """,
            countQuery = """
            SELECT COUNT(DISTINCT u) FROM User u JOIN u.roles r
            WHERE u.organization.id = :organizationId
              AND r.name = com.vulnscanner.application.role.RoleName.SECURITY_ANALYST
              AND (:status IS NULL OR u.status = :status)
              AND (:search IS NULL OR LOWER(CONCAT(COALESCE(u.firstName, ''), ' ',
                  COALESCE(u.lastName, ''))) LIKE LOWER(CONCAT('%', :search, '%')))
            """)
    Page<User> searchOrganizationUsers(@Param("organizationId") Long organizationId,
                                       @Param("status") UserStatus status,
                                       @Param("search") String search,
                                       Pageable pageable);

    @Query(value = """
            SELECT DISTINCT u FROM User u JOIN u.roles r
            WHERE u.organization.id = :organizationId
              AND u.status = :status
              AND r.name = com.vulnscanner.application.role.RoleName.SECURITY_ANALYST
            """,
            countQuery = """
            SELECT COUNT(DISTINCT u) FROM User u JOIN u.roles r
            WHERE u.organization.id = :organizationId
              AND u.status = :status
              AND r.name = com.vulnscanner.application.role.RoleName.SECURITY_ANALYST
            """)
    Page<User> findEligibleApprovalRequests(@Param("organizationId") Long organizationId,
                                            @Param("status") UserStatus status,
                                            Pageable pageable);

    @Query(value = """
            SELECT DISTINCT u FROM User u JOIN u.roles r
            WHERE r.name = com.vulnscanner.application.role.RoleName.ADMIN
              AND u.organization IS NOT NULL
              AND SIZE(u.roles) = 1
              AND u.organization.status = com.vulnscanner.application.organization.OrganizationStatus.APPROVED
              AND u.status <> com.vulnscanner.application.user.UserStatus.PENDING_APPROVAL
              AND (:status IS NULL OR u.status = :status)
            """,
            countQuery = """
            SELECT COUNT(DISTINCT u) FROM User u JOIN u.roles r
            WHERE r.name = com.vulnscanner.application.role.RoleName.ADMIN
              AND u.organization IS NOT NULL
              AND SIZE(u.roles) = 1
              AND u.organization.status = com.vulnscanner.application.organization.OrganizationStatus.APPROVED
              AND u.status <> com.vulnscanner.application.user.UserStatus.PENDING_APPROVAL
              AND (:status IS NULL OR u.status = :status)
            """)
    Page<User> findOrganizationAdmins(@Param("status") UserStatus status, Pageable pageable);

    @Query("""
            SELECT COUNT(DISTINCT u) FROM User u JOIN u.roles r
            WHERE u.organization.id = :organizationId
              AND u.status = :status
              AND SIZE(u.roles) = 1
              AND r.name = com.vulnscanner.application.role.RoleName.ADMIN
            """)
    long countOrganizationAdminsByStatus(@Param("organizationId") Long organizationId,
                                         @Param("status") UserStatus status);

    @Query("""
            SELECT CASE WHEN COUNT(DISTINCT u) > 0 THEN true ELSE false END
            FROM User u JOIN u.roles r
            WHERE u.organization.id = :organizationId
              AND u.status = com.vulnscanner.application.user.UserStatus.ACTIVE
              AND r.name = com.vulnscanner.application.role.RoleName.SUPER_ADMIN
            """)
    boolean existsActiveSuperAdminInOrganization(@Param("organizationId") Long organizationId);

    @Modifying
    @Query("UPDATE User u SET u.organization = null WHERE u.organization.id = :orgId")
    void detachUsersFromOrganization(@Param("orgId") Long orgId);
}
