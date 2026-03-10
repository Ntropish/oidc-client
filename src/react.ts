import { createContext, useContext, useState, useEffect, createElement } from 'react';
import type { ReactNode } from 'react';
import type { OidcClient } from './client';
import type { OidcUser } from './types';

interface AuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: OidcUser | null;
  login: () => Promise<void>;
  logout: () => Promise<void>;
  getAccessToken: () => Promise<string>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({
  client,
  children,
}: {
  client: OidcClient;
  children: ReactNode;
}) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState<OidcUser | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function init() {
      try {
        // Check if this is a callback from the auth server
        const params = new URLSearchParams(window.location.search);
        if (params.has('code')) {
          const user = await client.handleCallback();
          if (!cancelled) {
            setUser(user);
            setIsAuthenticated(true);
          }
        } else if (client.isAuthenticated()) {
          if (!cancelled) {
            setUser(client.getUser());
            setIsAuthenticated(true);
          }
        }
      } catch (err) {
        console.error('Auth initialization failed:', err);
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    }

    init();
    return () => { cancelled = true; };
  }, [client]);

  const value: AuthContextValue = {
    isAuthenticated,
    isLoading,
    user,
    login: () => client.login(),
    logout: async () => {
      await client.logout();
      setIsAuthenticated(false);
      setUser(null);
    },
    getAccessToken: () => client.getAccessToken(),
  };

  return createElement(AuthContext.Provider, { value }, children);
}

function useAuthContext(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth/useUser must be used within <AuthProvider>');
  return ctx;
}

export function useAuth() {
  const { isAuthenticated, isLoading, login, logout, getAccessToken } = useAuthContext();
  return { isAuthenticated, isLoading, login, logout, getAccessToken };
}

export function useUser() {
  const { user, isLoading } = useAuthContext();
  return { user, isLoading };
}
