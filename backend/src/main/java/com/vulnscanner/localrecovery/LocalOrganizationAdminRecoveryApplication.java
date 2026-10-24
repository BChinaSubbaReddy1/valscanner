package com.vulnscanner.localrecovery;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;

public final class LocalOrganizationAdminRecoveryApplication {

    private LocalOrganizationAdminRecoveryApplication() {
    }

    public static void main(String[] args) {
        new SpringApplicationBuilder(LocalOrganizationAdminRecoveryConfiguration.class)
                .web(WebApplicationType.NONE)
                .properties("local.organization-admin-recovery.enabled=true")
                .run(args);
    }
}
