package com.vulnscanner.localrecovery;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.Console;
import java.util.Arrays;

@Component
@ConditionalOnProperty(name = "local.organization-admin-recovery.enabled", havingValue = "true")
public class LocalOrganizationAdminRecoveryRunner implements ApplicationRunner {
    private final LocalOrganizationAdminRecoveryService recoveryService;

    public LocalOrganizationAdminRecoveryRunner(LocalOrganizationAdminRecoveryService recoveryService) {
        this.recoveryService = recoveryService;
    }

    @Override
    public void run(ApplicationArguments args) {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("A real interactive terminal is required; no account changes were made.");
        }

        char[] superAdminPassword = null;
        char[] superAdminConfirmation = null;
        char[] labPassword = null;
        char[] labConfirmation = null;
        char[] dockerPassword = null;
        char[] dockerConfirmation = null;
        try {
            superAdminPassword = console.readPassword("New password for Super Admin (admin@company.com): ");
            superAdminConfirmation = console.readPassword("Confirm Super Admin password: ");
            labPassword = console.readPassword("New password for Lab admin (bcsr@pa.com): ");
            labConfirmation = console.readPassword("Confirm Lab admin password: ");
            dockerPassword = console.readPassword("New password for Docker admin (sunnybuddareddy17@gmail.com): ");
            dockerConfirmation = console.readPassword("Confirm Docker admin password: ");
            if (superAdminPassword == null || superAdminConfirmation == null
                    || labPassword == null || labConfirmation == null
                    || dockerPassword == null || dockerConfirmation == null) {
                throw new IllegalStateException("Password entry was cancelled; no account changes were made.");
            }
            if (!Arrays.equals(superAdminPassword, superAdminConfirmation)
                    || !Arrays.equals(labPassword, labConfirmation)
                    || !Arrays.equals(dockerPassword, dockerConfirmation)) {
                throw new IllegalArgumentException("Password confirmations did not match; no account changes were made.");
            }

            LocalOrganizationAdminRecoveryService.RecoveryResult result = recoveryService.recover(
                    new String(superAdminPassword), new String(labPassword), new String(dockerPassword));
            console.printf("Recovery completed and verified. Super Admin user %d; Lab user %d remains in organization %d; "
                            + "Docker user %d remains in organization %d.%n",
                    result.superAdminUserId(),
                    result.labUserId(), result.labOrganizationId(),
                    result.dockerUserId(), result.dockerOrganizationId());
        } finally {
            clear(superAdminPassword);
            clear(superAdminConfirmation);
            clear(labPassword);
            clear(labConfirmation);
            clear(dockerPassword);
            clear(dockerConfirmation);
        }
    }

    private void clear(char[] password) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }
}
