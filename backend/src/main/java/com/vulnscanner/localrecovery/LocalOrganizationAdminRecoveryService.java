package com.vulnscanner.localrecovery;

import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class LocalOrganizationAdminRecoveryService {
    static final String SUPER_ADMIN_OLD_EMAIL = "lab-admin@localhost.invalid";
    static final String SUPER_ADMIN_NEW_EMAIL = "admin@company.com";
    static final String LAB_OLD_EMAIL = "lab-admin-20261022230400@example.invalid";
    static final String LAB_NEW_EMAIL = "bcsr@pa.com";
    static final String DOCKER_OLD_EMAIL = "docker-admin-20261022233612@example.invalid";
    static final String DOCKER_NEW_EMAIL = "sunnybuddareddy17@gmail.com";

    private static final Pattern MYSQL_URL =
            Pattern.compile("^jdbc:mysql://([^/:?]+)(?::(\\d+))?/([^?]+)(?:\\?.*)?$", Pattern.CASE_INSENSITIVE);
    private static final int MAX_BCRYPT_PASSWORD_BYTES = 72;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TransactionTemplate transactionTemplate;
    private final DataSource dataSource;

    public LocalOrganizationAdminRecoveryService(UserRepository userRepository,
                                                 PasswordEncoder passwordEncoder,
                                                 TransactionTemplate transactionTemplate,
                                                 DataSource dataSource) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.transactionTemplate = transactionTemplate;
        this.dataSource = dataSource;
    }

    public RecoveryResult recover(String superAdminPassword, String labPassword, String dockerPassword) {
        validatePassword(superAdminPassword);
        validatePassword(labPassword);
        validatePassword(dockerPassword);

        try {
            RecoveryTransactionResult committedResult = transactionTemplate.execute(status -> {
                requireLocalDatabase();
                User superAdmin = userRepository.findByEmailForUpdate(SUPER_ADMIN_OLD_EMAIL)
                        .or(() -> userRepository.findByEmailForUpdate(SUPER_ADMIN_NEW_EMAIL))
                        .orElseThrow(() -> new IllegalStateException(
                                "The existing Super Admin account was not found at its current or requested email."));
                // Fall back to the already-migrated (new) email for each account, same as the Super
                // Admin lookup above, so recover() is idempotent: running it again after a
                // successful migration (e.g. to rotate a forgotten password) still finds the
                // account instead of failing with "account was not found" just because the old
                // placeholder email no longer exists.
                User labUser = userRepository.findByEmailForUpdate(LAB_OLD_EMAIL)
                        .or(() -> userRepository.findByEmailForUpdate(LAB_NEW_EMAIL))
                        .orElseThrow(() -> new IllegalStateException(
                                "The existing Lab admin account was not found at its current or requested email."));
                User dockerUser = userRepository.findByEmailForUpdate(DOCKER_OLD_EMAIL)
                        .or(() -> userRepository.findByEmailForUpdate(DOCKER_NEW_EMAIL))
                        .orElseThrow(() -> new IllegalStateException(
                                "The existing Docker admin account was not found at its current or requested email."));

                AccountSnapshot superAdminSnapshot = snapshot(superAdmin);
                AccountSnapshot labSnapshot = snapshot(labUser);
                AccountSnapshot dockerSnapshot = snapshot(dockerUser);
                validateAdminAccount(labUser, "Lab");
                validateAdminAccount(dockerUser, "Docker");
                validateSuperAdminAccount(superAdmin);
                if (labUser.getId().equals(dockerUser.getId())
                        || labUser.getOrganization().getId().equals(dockerUser.getOrganization().getId())) {
                    throw new IllegalStateException("The existing admin accounts do not have distinct organization associations.");
                }

                requireEmailAvailable(SUPER_ADMIN_NEW_EMAIL, superAdmin.getId());
                requireEmailAvailable(LAB_NEW_EMAIL, labUser.getId());
                requireEmailAvailable(DOCKER_NEW_EMAIL, dockerUser.getId());

                String superAdminEncodedPassword = passwordEncoder.encode(superAdminPassword);
                String labEncodedPassword = passwordEncoder.encode(labPassword);
                String dockerEncodedPassword = passwordEncoder.encode(dockerPassword);
                requireSingleUpdate(userRepository.updateEmailAndPassword(
                        superAdmin.getId(), SUPER_ADMIN_NEW_EMAIL, superAdminEncodedPassword));
                requireSingleUpdate(userRepository.updateEmailAndPassword(
                        labUser.getId(), LAB_NEW_EMAIL, labEncodedPassword));
                requireSingleUpdate(userRepository.updateEmailAndPassword(
                        dockerUser.getId(), DOCKER_NEW_EMAIL, dockerEncodedPassword));

                verifyAccount(SUPER_ADMIN_NEW_EMAIL, superAdminSnapshot, superAdminPassword);
                verifyAccount(LAB_NEW_EMAIL, labSnapshot, labPassword);
                verifyAccount(DOCKER_NEW_EMAIL, dockerSnapshot, dockerPassword);
                return new RecoveryTransactionResult(
                        new RecoveryResult(superAdmin.getId(),
                                labUser.getId(), labUser.getOrganization().getId(),
                                dockerUser.getId(), dockerUser.getOrganization().getId()),
                        superAdminSnapshot, labSnapshot, dockerSnapshot);
            });
            if (committedResult == null) {
                throw new IllegalStateException("The account recovery transaction did not complete.");
            }

            verifyAccount(SUPER_ADMIN_NEW_EMAIL, committedResult.superAdminSnapshot(), superAdminPassword);
            verifyAccount(LAB_NEW_EMAIL, committedResult.labSnapshot(), labPassword);
            verifyAccount(DOCKER_NEW_EMAIL, committedResult.dockerSnapshot(), dockerPassword);
            return committedResult.recoveryResult();
        } catch (DataIntegrityViolationException conflict) {
            throw new IllegalStateException(
                    "The database rejected the account updates; all changes were rolled back. Check for an email conflict.");
        }
    }

    private void validatePassword(String password) {
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("All new passwords are required.");
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_BCRYPT_PASSWORD_BYTES) {
            throw new IllegalArgumentException("A new password exceeds the supported BCrypt length.");
        }
    }

    private void validateAdminAccount(User user, String label) {
        Set<RoleName> roles = user.getRoles().stream().map(role -> role.getName())
                .collect(java.util.stream.Collectors.toSet());
        if (user.getStatus() != UserStatus.ACTIVE
                || user.getOrganization() == null
                || user.getOrganization().getStatus() != OrganizationStatus.APPROVED
                || !roles.equals(Set.of(RoleName.ADMIN))) {
            throw new IllegalStateException(label + " account is not an active, approved-organization ADMIN account.");
        }
    }

    private void validateSuperAdminAccount(User user) {
        if (!user.getRoles().stream().map(role -> role.getName()).collect(java.util.stream.Collectors.toSet())
                .contains(RoleName.SUPER_ADMIN)) {
            throw new IllegalStateException("The existing account does not have the SUPER_ADMIN role.");
        }
    }

    private void requireEmailAvailable(String email, Long expectedAccountId) {
        userRepository.findByEmailIgnoreCase(email).ifPresent(existing -> {
            if (!existing.getId().equals(expectedAccountId)) {
                throw new IllegalStateException("A requested new email is already assigned to another account.");
            }
        });
    }

    private void requireSingleUpdate(int rowsUpdated) {
        if (rowsUpdated != 1) {
            throw new IllegalStateException("An account update did not affect exactly one existing account.");
        }
    }

    private AccountSnapshot snapshot(User user) {
        Set<RoleName> roles = user.getRoles().stream().map(role -> role.getName())
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        Long organizationId = user.getOrganization() == null ? null : user.getOrganization().getId();
        return new AccountSnapshot(user.getId(), organizationId, user.getStatus(), roles);
    }

    private void verifyAccount(String email, AccountSnapshot expected, String rawPassword) {
        User updated = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new IllegalStateException("Post-update account verification failed."));
        if (!updated.getId().equals(expected.userId())
                || !java.util.Objects.equals(
                        updated.getOrganization() == null ? null : updated.getOrganization().getId(),
                        expected.organizationId())
                || updated.getStatus() != expected.status()
                || !updated.getRoles().stream().map(role -> role.getName())
                        .collect(java.util.stream.Collectors.toSet()).equals(expected.roles())
                || !passwordEncoder.matches(rawPassword, updated.getPassword())) {
            throw new IllegalStateException("Post-update account verification failed.");
        }
    }

    private void requireLocalDatabase() {
        try {
            Connection connection = DataSourceUtils.getConnection(dataSource);
            try {
                DatabaseMetaData metaData = connection.getMetaData();
                if (!isLocalDatabaseUrl(metaData.getURL())) {
                    throw new IllegalStateException("Recovery is restricted to a local MySQL or in-memory H2 database.");
                }
            } finally {
                DataSourceUtils.releaseConnection(connection, dataSource);
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to verify that the database is local.", exception);
        }
    }

    static boolean isLocalDatabaseUrl(String url) {
        if (url == null) {
            return false;
        }
        String normalized = url.toLowerCase(Locale.ROOT);
        if (normalized.startsWith("jdbc:h2:mem:")) {
            return true;
        }

        Matcher matcher = MYSQL_URL.matcher(url);
        if (!matcher.matches()) {
            return false;
        }
        String host = matcher.group(1).toLowerCase(Locale.ROOT);
        int port = matcher.group(2) == null ? 3306 : Integer.parseInt(matcher.group(2));
        return (host.equals("localhost") || host.equals("127.0.0.1"))
                && (port == 3306 || port == 3307);
    }

    private record AccountSnapshot(Long userId, Long organizationId, UserStatus status, Set<RoleName> roles) {
    }

    private record RecoveryTransactionResult(RecoveryResult recoveryResult,
                                             AccountSnapshot superAdminSnapshot,
                                             AccountSnapshot labSnapshot,
                                             AccountSnapshot dockerSnapshot) {
    }

    public record RecoveryResult(Long superAdminUserId, Long labUserId, Long labOrganizationId,
                                 Long dockerUserId, Long dockerOrganizationId) {
    }
}
