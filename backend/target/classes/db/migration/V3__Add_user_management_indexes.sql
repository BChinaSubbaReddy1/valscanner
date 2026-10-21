CREATE INDEX idx_users_org_status ON users (organization_id, status);
CREATE INDEX idx_user_roles_role_user ON user_roles (role_id, user_id);
