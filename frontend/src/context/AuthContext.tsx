import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { apiEvents } from '../services/apiEvents';
import { getAuthToken, setAuthToken, clearAuthToken } from '../services/authStorage';
import {
  AuthUser,
  AuthTokenResponse,
  LoginPayload,
  RegisterPayload,
  loginAccount,
  registerAccount,
  getCurrentUser,
} from '../services/api';
import { ALL_ASSIGNABLE_ROLES, CROSS_ORG_ROLES, ADMIN_ROLES, ORG_ASSIGNABLE_ROLES, RoleCode } from '../constants/rbac';

interface AuthContextValue {
  user: AuthUser | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  /** True only while the initial "is there a valid session?" check is running. */
  isLoading: boolean;
  /**
   * Set when an active session was invalidated mid-use (a 401 from any
   * call), so the login screen can explain why the person is looking at it
   * again. Cleared as soon as a new session is established.
   */
  sessionMessage: string | null;
  login: (emailOrUsername: string, password: string) => Promise<void>;
  register: (payload: RegisterPayload) => Promise<void>;
  logout: () => void;
  clearSessionMessage: () => void;
  isAdmin: () => boolean;
  isCrossOrg: () => boolean;
  canInvite: () => boolean;
  canManageRole: (targetRole: string) => boolean;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [sessionMessage, setSessionMessage] = useState<string | null>(null);

  // Tracks whether we've ever established a real session in this tab, so the
  // "unauthorized" event handler can tell "token expired mid-session" (show
  // a message) apart from "no/invalid token on initial load" (stay quiet).
  const hadSessionRef = useRef(false);

  const applySession = useCallback((response: AuthTokenResponse) => {
    setAuthToken(response.access_token);
    setAccessToken(response.access_token);
    setUser(response.user);
    setIsAuthenticated(true);
    setSessionMessage(null);
    hadSessionRef.current = true;
  }, []);

  const login = useCallback(
    async (emailOrUsername: string, password: string) => {
      const payload: LoginPayload = {
        identifier: emailOrUsername,
        email: emailOrUsername,
        password,
      };
      const response = await loginAccount(payload);
      applySession(response);
    },
    [applySession]
  );

  const register = useCallback(
    async (payload: RegisterPayload) => {
      const response = await registerAccount(payload);
      applySession(response);
    },
    [applySession]
  );

  const logout = useCallback(() => {
    clearAuthToken();
    setAccessToken(null);
    setUser(null);
    setIsAuthenticated(false);
    setSessionMessage(null);
    hadSessionRef.current = false;
  }, []);

  const clearSessionMessage = useCallback(() => setSessionMessage(null), []);
  const isAdmin = useCallback(() => !!user && ADMIN_ROLES.includes(user.role as RoleCode), [user]);
  const isCrossOrg = useCallback(() => !!user && CROSS_ORG_ROLES.includes(user.role as RoleCode), [user]);
  const canInvite = useCallback(() => isAdmin(), [isAdmin]);
  const canManageRole = useCallback((targetRole: string) => {
    if (!user) return false;
    return user.role === 'SYSTEM_ADMIN'
      ? ALL_ASSIGNABLE_ROLES.includes(targetRole as RoleCode)
      : user.role === 'INSTITUTION_ADMIN' && ORG_ASSIGNABLE_ROLES.includes(targetRole as RoleCode);
  }, [user]);

  // On mount: if a token survived (same-tab reload), validate it against
  // GET /auth/me before trusting it. Anything other than a clean 200 means
  // the token is stale/invalid -- clear it silently and fall through to the
  // login screen rather than showing a broken authenticated shell.
  useEffect(() => {
    const token = getAuthToken();
    if (!token) {
      setIsLoading(false);
      return;
    }
    setAccessToken(token);
    (async () => {
      try {
        const me = await getCurrentUser();
        setUser(me);
        setIsAuthenticated(true);
        hadSessionRef.current = true;
      } catch {
        clearAuthToken();
        setAccessToken(null);
        setIsAuthenticated(false);
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  // Fired by the axios response interceptor on any 401, from anywhere in the
  // app (services/api.ts already cleared the stored token by the time this
  // runs). Only surface a "your session expired" message if we had actually
  // been signed in -- not for a stale/invalid token discovered on first load.
  useEffect(() => {
    return apiEvents.on('unauthorized', () => {
      if (hadSessionRef.current) {
        setSessionMessage('Your session expired, please sign in again.');
      }
      hadSessionRef.current = false;
      setAccessToken(null);
      setUser(null);
      setIsAuthenticated(false);
    });
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        accessToken,
        isAuthenticated,
        isLoading,
        sessionMessage,
        login,
        register,
        logout,
        clearSessionMessage,
        isAdmin,
        isCrossOrg,
        canInvite,
        canManageRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
