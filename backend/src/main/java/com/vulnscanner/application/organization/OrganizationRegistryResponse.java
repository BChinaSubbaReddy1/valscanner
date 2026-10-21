package com.vulnscanner.application.organization;

import java.util.List;

public record OrganizationRegistryResponse(
        OrganizationRegistryItem ownOrganization,
        List<OrganizationRegistryItem> approvedOrganizations
) {
}
