package com.vulnscanner.application.security;

import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {
    boolean existsByJti(String jti);
    void deleteByExpiresAtBefore(java.time.Instant instant);
}
