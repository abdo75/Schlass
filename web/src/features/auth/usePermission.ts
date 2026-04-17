import { useAuth } from "./AuthContext";
import { permissionsForRole, type Permission } from "./permissions";

// Returns true iff the authenticated user's role holds the permission.
// Returns false when unauthenticated — callers can use this as a combined
// "is-signed-in + has-permission" check without an extra `user` null guard.
export function usePermission(perm: Permission): boolean {
  const { user } = useAuth();
  if (!user) return false;
  return permissionsForRole(user.role).includes(perm);
}
