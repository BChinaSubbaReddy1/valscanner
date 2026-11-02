package com.vulnscanner.application.user;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface LoginOtpChallengeRepository extends JpaRepository<LoginOtpChallenge, Long> {
    Optional<LoginOtpChallenge> findByChallengeTokenHash(String challengeTokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM LoginOtpChallenge c WHERE c.user.id = :userId")
    Optional<LoginOtpChallenge> findByUserIdForUpdate(@Param("userId") Long userId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM LoginOtpChallenge c WHERE c.challengeTokenHash = :challengeTokenHash")
    Optional<LoginOtpChallenge> findByChallengeTokenHashForUpdate(
            @Param("challengeTokenHash") String challengeTokenHash);
}
