package com.vulnscanner.application.security;

import com.vulnscanner.application.user.User;
import com.vulnscanner.application.role.RoleName;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

public class UserPrincipal implements UserDetails {
    private final Long id;
    private final String email;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;
    private final boolean accountNonLocked;
    private final boolean enabled;
    private final Long organizationId;

    public UserPrincipal(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.authorities = user.getRoles().stream()
                .filter(role -> role.getName() != RoleName.CUSTOMER)
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName().name()))
                .collect(Collectors.toSet());
        this.accountNonLocked = user.getStatus() != com.vulnscanner.application.user.UserStatus.LOCKED;
        this.enabled = user.getStatus() == com.vulnscanner.application.user.UserStatus.ACTIVE &&
                (user.getOrganization() == null ||
                        user.getOrganization().getStatus() == com.vulnscanner.application.organization.OrganizationStatus.APPROVED) &&
                user.getRoles().stream().anyMatch(role -> role.getName() != RoleName.CUSTOMER);
        this.organizationId = user.getOrganization() != null ? user.getOrganization().getId() : null;
    }

    public Long getId() {
        return id;
    }

    public Long getOrganizationId() {
        return organizationId;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
