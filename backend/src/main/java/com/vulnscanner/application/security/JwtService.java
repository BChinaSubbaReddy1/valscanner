package com.vulnscanner.application.security;

import com.vulnscanner.application.config.JwtProperties;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class JwtService {
    private final JwtProperties properties;
    private final TokenBlacklistRepository tokenBlacklistRepository;
    private Key signingKey;

    public JwtService(JwtProperties properties, TokenBlacklistRepository tokenBlacklistRepository) {
        this.properties = properties;
        this.tokenBlacklistRepository = tokenBlacklistRepository;
    }

    @PostConstruct
    public void init() {
        if (properties.getSecret() == null || properties.getSecret().isBlank()) {
            throw new IllegalStateException("JWT secret must be configured");
        }
        this.signingKey = Keys.hmacShaKeyFor(properties.getSecret().getBytes());
    }

    public String generateToken(User user) {
        String jti = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(properties.getExpirationMs());
        List<String> roles = user.getRoles().stream()
                .filter(role -> role.getName() != RoleName.CUSTOMER)
                .map(role -> role.getName().name()).toList();

        return Jwts.builder()
                .setSubject(user.getEmail())
                .claim("userId", user.getId())
                .claim("roles", roles)
                .claim("organizationId", user.getOrganization() == null ? null : user.getOrganization().getId())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiry))
                .setId(jti)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = parseClaims(token);
            if (claims.getExpiration().before(Date.from(Instant.now()))) {
                return false;
            }
            if (properties.isBlacklistEnabled() && tokenBlacklistRepository.existsByJti(claims.getId())) {
                return false;
            }
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    public String extractUserEmail(String token) {
        return parseClaims(token).getSubject();
    }

    public void invalidateToken(String token) {
        try {
            Claims claims = parseClaims(token);
            tokenBlacklistRepository.save(new TokenBlacklist(claims.getId(), claims.getExpiration().toInstant()));
        } catch (JwtException | IllegalArgumentException ignored) {
            // Ignore malformed tokens during logout.
        }
    }
}
