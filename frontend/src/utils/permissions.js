export const ROLES = ['SUPER_ADMIN', 'ADMIN', 'SECURITY_ANALYST'];

const ROLE_LABELS = {
  SUPER_ADMIN: 'Super Admin',
  ADMIN: 'Organization Admin',
  SECURITY_ANALYST: 'Security Analyst',
};

const normalizeRole = (role) => String(role || '').trim().toUpperCase();

export function getUserRoles(user = {}) {
  const candidates = [];

  if (Array.isArray(user.roles)) {
    candidates.push(...user.roles);
  }

  if (Array.isArray(user.authorities)) {
    candidates.push(...user.authorities);
  }

  if (typeof user.role === 'string') {
    candidates.push(user.role);
  }

  if (typeof user.roleName === 'string') {
    candidates.push(user.roleName);
  }

  return [...new Set(candidates.map(normalizeRole).filter(Boolean))];
}

export function hasRole(user, role) {
  return getUserRoles(user).includes(normalizeRole(role));
}

export function getRoleLabel(role) {
  const normalized = normalizeRole(role);
  return ROLE_LABELS[normalized] || 'Unrecognized role';
}

export function canManageOrganizations(user) {
  return hasRole(user, 'SUPER_ADMIN');
}

export function canManageTargets(user) {
  return hasRole(user, 'ADMIN');
}

export function canViewAnalystWorkspace(user) {
  return hasRole(user, 'SECURITY_ANALYST');
}

export function canViewReports(user) {
  return hasRole(user, 'ADMIN') || hasRole(user, 'SECURITY_ANALYST');
}
