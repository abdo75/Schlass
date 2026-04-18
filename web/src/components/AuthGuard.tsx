import { Navigate, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "@/features/auth/AuthContext";

export function AuthGuard({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;

  // Forced password change flow: if the user hasn't changed their temp
  // password yet, redirect them to /change-password unless they're already
  // there. Prevents infinite redirect loops.
  if (user.force_password_change && location.pathname !== "/change-password") {
    return <Navigate to="/change-password" replace />;
  }

  // Forced MFA enrollment: redirect to /setup-mfa unless already there.
  // Order matters: force_password_change takes precedence over force_mfa_enrollment
  // so a user with both flags goes through change-password first.
  if (user.force_mfa_enrollment && location.pathname !== "/setup-mfa") {
    return <Navigate to="/setup-mfa" replace />;
  }

  return <>{children}</>;
}
