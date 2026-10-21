import { useCallback, useEffect, useMemo, useState } from 'react';
import { authApi, readStoredSession, writeSession } from '../api/client';
import { AuthContext } from './authContext';

function normalizeRoles(input) {
  const raw = Array.isArray(input) ? input : [input].filter(Boolean);

  return raw
    .flatMap((value) => {
      if (Array.isArray(value)) {
        return value;
      }

      if (typeof value === 'string') {
        return [value];
      }

      return [];
    })
    .map((item) => String(item).trim().toUpperCase())
    .filter(Boolean);
}

function normalizeUser(payload = {}) {
  const unwrapped = (payload && typeof payload === 'object' && payload.data && typeof payload.data === 'object')
    ? payload.data
    : payload;
  const user = unwrapped.user || unwrapped.profile || unwrapped;
  const roles = normalizeRoles(user.roles || user.role || user.authorities || unwrapped.roles || unwrapped.role || unwrapped.authorities);

  return {
    ...user,
    id: user.id || unwrapped.userId || unwrapped.id || null,
    username: user.username || user.email || unwrapped.username || unwrapped.email || 'user',
    email: user.email || unwrapped.email || '',
    roles,
    organizationId: user.organizationId || user.organization?.id || unwrapped.organizationId || null,
  };
}

function normalizeSession(payload) {
  const unwrapped = (payload && typeof payload === 'object' && payload.data && typeof payload.data === 'object')
    ? payload.data
    : payload;
  const token = unwrapped?.token || unwrapped?.accessToken || unwrapped?.jwt || unwrapped?.access_token || null;
  const user = normalizeUser(payload);

  return {
    token,
    user,
  };
}

export function AuthProvider({ children }) {
  const [session, setSession] = useState(() => readStoredSession());

  useEffect(() => {
    if (session) {
      writeSession(session);
      return;
    }

    writeSession(null);
  }, [session]);

  useEffect(() => {
    const onSessionExpired = () => {
      setSession(null);
    };

    window.addEventListener('auth:session-expired', onSessionExpired);
    return () => window.removeEventListener('auth:session-expired', onSessionExpired);
  }, []);

  const login = async (credentials) => {
    const result = await authApi.login(credentials);
    let nextSession = normalizeSession(result);

    if (!nextSession.token) {
      throw new Error('Authentication token was not returned by the backend.');
    }

    writeSession(nextSession);
    try {
      const profile = normalizeUser(await authApi.currentUser());
      nextSession = {
        ...nextSession,
        user: { ...nextSession.user, ...profile },
      };
    } catch (requestError) {
      writeSession(null);
      throw requestError;
    }

    setSession(nextSession);
    return nextSession;
  };

  const register = async (payload) => {
    const result = await authApi.register(payload);
    const nextSession = normalizeSession(result);

    if (nextSession.token) {
      setSession(nextSession);
    }

    return result;
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } finally {
      setSession(null);
    }
  };

  const refreshUser = useCallback(async () => {
    const profile = await authApi.currentUser();
    const nextUser = normalizeUser(profile);
    setSession((current) => ({
      token: current?.token || null,
      user: nextUser,
    }));
    return nextUser;
  }, []);

  const value = useMemo(() => ({
    session,
    user: session?.user || null,
    token: session?.token || null,
    isAuthenticated: Boolean(session?.token),
    loading: false,
    login,
    register,
    logout,
    refreshUser,
    setSession,
  }), [session, refreshUser]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
