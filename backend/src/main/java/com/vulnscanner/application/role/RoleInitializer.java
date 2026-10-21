package com.vulnscanner.application.role;

import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Component
public class RoleInitializer implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(RoleInitializer.class);

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.bootstrap.super-admin.email:}")
    private String superAdminEmail;

    @Value("${app.bootstrap.super-admin.password:}")
    private String superAdminPassword;

    public RoleInitializer(RoleRepository roleRepository,
                          UserRepository userRepository,
                          PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        for (RoleName name : new RoleName[]{
                RoleName.SUPER_ADMIN, RoleName.ADMIN, RoleName.SECURITY_ANALYST}) {
            roleRepository.findByName(name).orElseGet(() -> roleRepository.save(new Role(name)));
        }

        if (superAdminEmail == null || superAdminEmail.isBlank()) {
            log.info("No INITIAL_SUPER_ADMIN_EMAIL configured; skipping SUPER_ADMIN bootstrap.");
            return;
        }

        String normalizedEmail = superAdminEmail.trim().toLowerCase();

        userRepository.findByEmail(normalizedEmail).ifPresentOrElse(
                existing -> {
                    // Never silently promote or reset an existing account during bootstrap.
                    boolean alreadySuperAdmin = existing.getRoles().stream()
                            .anyMatch(role -> role.getName() == RoleName.SUPER_ADMIN);
                    if (alreadySuperAdmin) {
                        log.info("SUPER_ADMIN bootstrap account '{}' already exists; leaving it unchanged.", normalizedEmail);
                    } else {
                        log.warn("Bootstrap email '{}' is already registered with a different role set ({}). " +
                                        "Refusing to modify this account automatically; promote it manually if intended.",
                                normalizedEmail,
                                existing.getRoles().stream().map(r -> r.getName().name()).toList());
                    }
                },
                () -> createSuperAdmin(normalizedEmail)
        );
    }

    private void createSuperAdmin(String normalizedEmail) {
        if (superAdminPassword == null || superAdminPassword.isBlank()) {
            throw new IllegalStateException("Initial super admin password is required when email is configured");
        }

        try {
            User user = new User();
            user.setFirstName("System");
            user.setLastName("Administrator");
            user.setEmail(normalizedEmail);
            user.setPassword(passwordEncoder.encode(superAdminPassword));
            user.setStatus(UserStatus.ACTIVE);
            user.setRoles(Set.of(roleRepository.findByName(RoleName.SUPER_ADMIN).orElseThrow()));
            userRepository.save(user);
            log.info("Provisioned SUPER_ADMIN bootstrap account '{}'. Rotate this password before production use.",
                    normalizedEmail);
        } catch (DataIntegrityViolationException raceLost) {
            // Another instance won the race to create this account concurrently (unique email
            // constraint). That is the desired outcome under concurrent startup, so just log it.
            log.info("SUPER_ADMIN bootstrap account '{}' was created concurrently by another instance; skipping.",
                    normalizedEmail);
        }
    }
}
