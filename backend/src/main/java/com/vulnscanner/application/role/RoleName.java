package com.vulnscanner.application.role;

public enum RoleName {
    SUPER_ADMIN,
    ADMIN,
    SECURITY_ANALYST,
    // Retained so Hibernate can read legacy database assignments; not seeded or used by application workflows.
    CUSTOMER
}
