package com.vulnscanner.application.user;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface PasswordResetChallengeRepository extends JpaRepository<PasswordResetChallenge, Long> {
    Optional<PasswordResetChallenge> findByResetTokenHash(String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM PasswordResetChallenge c WHERE c.user.id = :userId")
    Optional<PasswordResetChallenge> findByUserIdForUpdate(@Param("userId") Long userId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM PasswordResetChallenge c WHERE c.resetTokenHash = :tokenHash")
    Optional<PasswordResetChallenge> findByResetTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    void deleteByUser(User user);
}
