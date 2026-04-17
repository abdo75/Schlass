import { Navigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "@/features/auth/AuthContext";

// AdminGuard wraps admin-only routes. It complements AuthGuard (which checks
// authentication) by additionally requiring the super_admin role — the
// shorthand v1 mapping for "holds any admin permission". A non-admin user
// who somehow reaches /admin (typed URL, bookmark, stale link) is redirected
// to /account, the end-user portal placeholder.
//
// When v2 introduces dynamic RBAC, the role check is replaced by a
// "holds at least one admin permission" check against the permission catalog.
// The redirect behavior does not change.
export function AdminGuard({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  if (user.role !== "super_admin") return <Navigate to="/account" replace />;

  return <>{children}</>;
}
