import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { getMe, login as apiLogin, logout as apiLogout, type AuthUser, type LoginResponse } from "./api";

interface AuthState {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string, returnTo?: string) => Promise<LoginResponse>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<AuthUser | null>;
}

// eslint-disable-next-line react-refresh/only-export-components -- exported for testing (provider construction)
export const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((res) => {
        if (!cancelled) setUser(res.user);
      })
      .catch(() => {
        if (!cancelled) setUser(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const handler = () => setUser(null);
    window.addEventListener("schlass:unauthorized", handler);
    return () => window.removeEventListener("schlass:unauthorized", handler);
  }, []);

  const login = async (email: string, password: string, returnTo?: string): Promise<LoginResponse> => {
    const res = await apiLogin(email, password, returnTo);
    if (res.kind === "session") setUser(res.user);
    return res;
  };

  const logout = async () => {
    await apiLogout();
    setUser(null);
  };

  const refreshUser = async (): Promise<AuthUser | null> => {
    try {
      const res = await getMe();
      setUser(res.user);
      return res.user;
    } catch (err) {
      // Clearing on any error is a safe default: a 401 legitimately means the
      // session is gone, and a transient 500 will re-resolve on the next
      // AuthGuard check after the /login bounce. Log so transient failures
      // surface in devtools instead of looking like a silent logout.
      console.error("refreshUser failed", err);
      setUser(null);
      return null;
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components -- useAuth hook is colocated with AuthProvider by convention
export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
