package com.vulnscanner.localrecovery;

import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(
        classes = LocalOrganizationAdminRecoveryConfiguration.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles("test")
@Transactional
class LocalOrganizationAdminRecoveryServiceTest {
    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    private LocalOrganizationAdminRecoveryService recoveryService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private Organization labOrganization;
    private Organization dockerOrganization;
    private User superAdminUser;
    private User labUser;
    private User dockerUser;
    private Role adminRole;
    private Role superAdminRole;
    private String oldPassword;

    @BeforeEach
    void setUp() {
        adminRole = new Role(RoleName.ADMIN);
        entityManager.persist(adminRole);
        superAdminRole = new Role(RoleName.SUPER_ADMIN);
        entityManager.persist(superAdminRole);
        labOrganization = approvedOrganization("Lab Org");
        dockerOrganization = approvedOrganization("Docker Org");
        oldPassword = "old-password-for-test";
        superAdminUser = createSuperAdmin(LocalOrganizationAdminRecoveryService.SUPER_ADMIN_OLD_EMAIL);
        labUser = createAdmin(LocalOrganizationAdminRecoveryService.LAB_OLD_EMAIL, labOrganization);
        dockerUser = createAdmin(LocalOrganizationAdminRecoveryService.DOCKER_OLD_EMAIL, dockerOrganization);
        entityManager.flush();
        entityManager.refresh(superAdminUser);
        entityManager.refresh(labUser);
        entityManager.refresh(dockerUser);
    }

    @Test
    void updatesOnlyTheExistingAccountsEmailAndEncodedPassword() {
        Long superAdminId = superAdminUser.getId();
        Long labId = labUser.getId();
        Long dockerId = dockerUser.getId();
        Long labOrgId = labOrganization.getId();
        Long dockerOrgId = dockerOrganization.getId();
        Instant superAdminUpdatedAt = superAdminUser.getUpdatedAt();
        Instant labUpdatedAt = labUser.getUpdatedAt();
        Instant dockerUpdatedAt = dockerUser.getUpdatedAt();

        LocalOrganizationAdminRecoveryService.RecoveryResult result =
                recoveryService.recover("new-super-password", "new-lab-password", "new-docker-password");

        User updatedSuperAdmin = userRepository.findByEmail(LocalOrganizationAdminRecoveryService.SUPER_ADMIN_NEW_EMAIL)
                .orElseThrow();
        User updatedLab = userRepository.findByEmail(LocalOrganizationAdminRecoveryService.LAB_NEW_EMAIL).orElseThrow();
        User updatedDocker = userRepository.findByEmail(LocalOrganizationAdminRecoveryService.DOCKER_NEW_EMAIL).orElseThrow();
        assertEquals(superAdminId, result.superAdminUserId());
        assertEquals(labId, result.labUserId());
        assertEquals(dockerId, result.dockerUserId());
        assertEquals(superAdminId, updatedSuperAdmin.getId());
        assertEquals(Set.of(RoleName.SUPER_ADMIN),
                updatedSuperAdmin.getRoles().stream().map(Role::getName).collect(java.util.stream.Collectors.toSet()));
        assertEquals(UserStatus.ACTIVE, updatedSuperAdmin.getStatus());
        assertNull(updatedSuperAdmin.getOrganization());
        assertEquals(superAdminUpdatedAt, updatedSuperAdmin.getUpdatedAt());
        assertTrue(passwordEncoder.matches("new-super-password", updatedSuperAdmin.getPassword()));
        assertEquals(labOrgId, updatedLab.getOrganization().getId());
        assertEquals(dockerOrgId, updatedDocker.getOrganization().getId());
        assertEquals(UserStatus.ACTIVE, updatedLab.getStatus());
        assertEquals(UserStatus.ACTIVE, updatedDocker.getStatus());
        assertEquals(Set.of(RoleName.ADMIN), updatedLab.getRoles().stream().map(Role::getName).collect(java.util.stream.Collectors.toSet()));
        assertEquals(Set.of(RoleName.ADMIN), updatedDocker.getRoles().stream().map(Role::getName).collect(java.util.stream.Collectors.toSet()));
        assertEquals(labUpdatedAt, updatedLab.getUpdatedAt());
        assertEquals(dockerUpdatedAt, updatedDocker.getUpdatedAt());
        assertTrue(passwordEncoder.matches("new-lab-password", updatedLab.getPassword()));
        assertTrue(passwordEncoder.matches("new-docker-password", updatedDocker.getPassword()));
        assertFalse(passwordEncoder.matches(oldPassword, updatedSuperAdmin.getPassword()));
        assertFalse(passwordEncoder.matches(oldPassword, updatedLab.getPassword()));
        assertFalse(passwordEncoder.matches(oldPassword, updatedDocker.getPassword()));
    }

    @Test
    void recoversExistingSuperAdminAlreadyAtRequestedEmailWhenSourceEmailIsAbsent() {
        Long superAdminId = superAdminUser.getId();
        superAdminUser.setEmail(LocalOrganizationAdminRecoveryService.SUPER_ADMIN_NEW_EMAIL);
        entityManager.flush();

        LocalOrganizationAdminRecoveryService.RecoveryResult result =
                recoveryService.recover("new-super-password", "new-lab-password", "new-docker-password");

        User updatedSuperAdmin = userRepository.findByEmailIgnoreCase(
                LocalOrganizationAdminRecoveryService.SUPER_ADMIN_NEW_EMAIL).orElseThrow();
        assertEquals(superAdminId, result.superAdminUserId());
        assertEquals(superAdminId, updatedSuperAdmin.getId());
        assertEquals(Set.of(RoleName.SUPER_ADMIN),
                updatedSuperAdmin.getRoles().stream().map(Role::getName).collect(java.util.stream.Collectors.toSet()));
        assertEquals(UserStatus.ACTIVE, updatedSuperAdmin.getStatus());
        assertNull(updatedSuperAdmin.getOrganization());
        assertTrue(passwordEncoder.matches("new-super-password", updatedSuperAdmin.getPassword()));
    }

    @Test
    void recoverIsIdempotentWhenAllThreeAccountsAreAlreadyAtTheirRequestedEmail() {
        // Simulates re-running the tool after a previous successful migration (e.g. to rotate a
        // forgotten password): none of the three legacy placeholder emails exist anymore, every
        // account is already at its new email.
        Long superAdminId = superAdminUser.getId();
        Long labId = labUser.getId();
        Long dockerId = dockerUser.getId();
        superAdminUser.setEmail(LocalOrganizationAdminRecoveryService.SUPER_ADMIN_NEW_EMAIL);
        labUser.setEmail(LocalOrganizationAdminRecoveryService.LAB_NEW_EMAIL);
        dockerUser.setEmail(LocalOrganizationAdminRecoveryService.DOCKER_NEW_EMAIL);
        entityManager.flush();

        LocalOrganizationAdminRecoveryService.RecoveryResult result =
                recoveryService.recover("rotated-super-password", "rotated-lab-password", "rotated-docker-password");

        assertEquals(superAdminId, result.superAdminUserId());
        assertEquals(labId, result.labUserId());
        assertEquals(dockerId, result.dockerUserId());
        User updatedSuperAdmin = userRepository.findByEmailIgnoreCase(
                LocalOrganizationAdminRecoveryService.SUPER_ADMIN_NEW_EMAIL).orElseThrow();
        User updatedLab = userRepository.findByEmailIgnoreCase(
                LocalOrganizationAdminRecoveryService.LAB_NEW_EMAIL).orElseThrow();
        User updatedDocker = userRepository.findByEmailIgnoreCase(
                LocalOrganizationAdminRecoveryService.DOCKER_NEW_EMAIL).orElseThrow();
        assertTrue(passwordEncoder.matches("rotated-super-password", updatedSuperAdmin.getPassword()));
        assertTrue(passwordEncoder.matches("rotated-lab-password", updatedLab.getPassword()));
        assertTrue(passwordEncoder.matches("rotated-docker-password", updatedDocker.getPassword()));
    }

    @Test
    void emailConflictLeavesBothExistingAccountsUnchanged() {
        createAdmin(LocalOrganizationAdminRecoveryService.SUPER_ADMIN_NEW_EMAIL.toUpperCase(),
                approvedOrganization("Conflict Org"));
        entityManager.flush();

        assertThrows(IllegalStateException.class,
                () -> recoveryService.recover("new-super-password", "new-lab-password", "new-docker-password"));

        assertTrue(userRepository.findByEmail(LocalOrganizationAdminRecoveryService.SUPER_ADMIN_OLD_EMAIL).isPresent());
        assertTrue(userRepository.findByEmail(LocalOrganizationAdminRecoveryService.LAB_OLD_EMAIL).isPresent());
        assertTrue(userRepository.findByEmail(LocalOrganizationAdminRecoveryService.DOCKER_OLD_EMAIL).isPresent());
        assertTrue(passwordEncoder.matches(oldPassword,
                userRepository.findByEmail(LocalOrganizationAdminRecoveryService.SUPER_ADMIN_OLD_EMAIL)
                        .orElseThrow().getPassword()));
        assertTrue(passwordEncoder.matches(oldPassword,
                userRepository.findByEmail(LocalOrganizationAdminRecoveryService.LAB_OLD_EMAIL).orElseThrow().getPassword()));
        assertTrue(passwordEncoder.matches(oldPassword,
                userRepository.findByEmail(LocalOrganizationAdminRecoveryService.DOCKER_OLD_EMAIL).orElseThrow().getPassword()));
    }

    @Test
    void nonAdminAccountsAreRejectedBeforeAnyChange() {
        Role analystRole = new Role(RoleName.SECURITY_ANALYST);
        entityManager.persist(analystRole);
        dockerUser.setRoles(Set.of(analystRole));
        entityManager.flush();

        assertThrows(IllegalStateException.class,
                () -> recoveryService.recover("new-super-password", "new-lab-password", "new-docker-password"));
        assertTrue(userRepository.findByEmail(LocalOrganizationAdminRecoveryService.SUPER_ADMIN_OLD_EMAIL).isPresent());
        assertTrue(userRepository.findByEmail(LocalOrganizationAdminRecoveryService.LAB_OLD_EMAIL).isPresent());
        assertTrue(userRepository.findByEmail(LocalOrganizationAdminRecoveryService.DOCKER_OLD_EMAIL).isPresent());
    }

    @Test
    void accountWithoutSuperAdminRoleIsRejectedBeforeAnyChange() {
        Role analystRole = new Role(RoleName.SECURITY_ANALYST);
        entityManager.persist(analystRole);
        superAdminUser.setRoles(Set.of(analystRole));
        entityManager.flush();

        assertThrows(IllegalStateException.class,
                () -> recoveryService.recover("new-super-password", "new-lab-password", "new-docker-password"));
        assertTrue(userRepository.findByEmail(LocalOrganizationAdminRecoveryService.SUPER_ADMIN_OLD_EMAIL).isPresent());
        assertTrue(userRepository.findByEmail(LocalOrganizationAdminRecoveryService.LAB_OLD_EMAIL).isPresent());
        assertTrue(userRepository.findByEmail(LocalOrganizationAdminRecoveryService.DOCKER_OLD_EMAIL).isPresent());
    }

    @Test
    void localDatabaseGuardAcceptsOnlyLoopbackAndComposeDatabaseUrls() {
        assertTrue(LocalOrganizationAdminRecoveryService.isLocalDatabaseUrl(
                "jdbc:mysql://127.0.0.1:3307/scanner?useSSL=false"));
        assertTrue(LocalOrganizationAdminRecoveryService.isLocalDatabaseUrl(
                "jdbc:h2:mem:vulnscanner"));
        assertFalse(LocalOrganizationAdminRecoveryService.isLocalDatabaseUrl(
                "jdbc:mysql://mysql:3306/scanner"));
        assertFalse(LocalOrganizationAdminRecoveryService.isLocalDatabaseUrl(
                "jdbc:h2:file://remote/share/vulnscanner"));
        assertFalse(LocalOrganizationAdminRecoveryService.isLocalDatabaseUrl(
                "jdbc:mysql://db.example.com:3306/scanner"));
        assertFalse(LocalOrganizationAdminRecoveryService.isLocalDatabaseUrl(
                "jdbc:mysql://192.168.1.10:3306/scanner"));
    }

    private Organization approvedOrganization(String name) {
        Organization organization = new Organization();
        organization.setName(name);
        organization.setContactEmail(name.replace(" ", "").toLowerCase() + "@example.test");
        organization.setPrimaryContactName("Test Owner");
        organization.setStatus(OrganizationStatus.APPROVED);
        entityManager.persist(organization);
        return organization;
    }

    private User createAdmin(String email, Organization organization) {
        User user = new User();
        user.setFirstName("Recovery");
        user.setLastName("Test");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(oldPassword));
        user.setStatus(UserStatus.ACTIVE);
        user.setOrganization(organization);
        user.setRoles(Set.of(adminRole));
        entityManager.persist(user);
        return user;
    }

    private User createSuperAdmin(String email) {
        User user = new User();
        user.setFirstName("Recovery");
        user.setLastName("Super Admin");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(oldPassword));
        user.setStatus(UserStatus.ACTIVE);
        user.setRoles(Set.of(superAdminRole));
        entityManager.persist(user);
        return user;
    }
}
