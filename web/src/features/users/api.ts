import { apiFetch } from "@/lib/api";
import type { AuthUser } from "@/features/auth/api";

export interface UserRow extends AuthUser {
  status: "active" | "disabled";
  created_at: string;
}

export interface UsersListResponse {
  users: UserRow[];
  total: number;
  limit: number;
  offset: number;
}

export interface UserSession {
  token: string;
  created_at: string;
  last_seen_at: string;
  ip_address: string;
  user_agent: string;
}

export interface UserDetailResponse {
  user: UserRow;
  sessions: UserSession[];
}

export interface CreateUserResponse {
  user: AuthUser;
  temporary_password: string;
}

export interface ResetPasswordResponse {
  temporary_password: string;
}

export function listUsers(
  limit = 50,
  offset = 0,
  emailSearch?: string,
): Promise<UsersListResponse> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  if (emailSearch) params.set("email", emailSearch);
  return apiFetch<UsersListResponse>(`/api/users?${params.toString()}`);
}

export function createUser(
  email: string,
  role: "super_admin" | "user",
): Promise<CreateUserResponse> {
  return apiFetch<CreateUserResponse>("/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, role }),
  });
}

export function getUser(id: string): Promise<UserDetailResponse> {
  return apiFetch<UserDetailResponse>(`/api/users/${id}`);
}

export function updateUser(
  id: string,
  patch: { email?: string; role?: string },
): Promise<{ user: AuthUser }> {
  return apiFetch<{ user: AuthUser }>(`/api/users/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
}

export function disableUser(id: string): Promise<void> {
  return apiFetch<void>(`/api/users/${id}/disable`, { method: "POST" });
}

export function enableUser(id: string): Promise<void> {
  return apiFetch<void>(`/api/users/${id}/enable`, { method: "POST" });
}

export function resetUserPassword(id: string): Promise<ResetPasswordResponse> {
  return apiFetch<ResetPasswordResponse>(`/api/users/${id}/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
}

export function deleteUser(id: string): Promise<void> {
  return apiFetch<void>(`/api/users/${id}`, { method: "DELETE" });
}

export function terminateAllSessions(id: string): Promise<void> {
  return apiFetch<void>(`/api/users/${id}/sessions`, { method: "DELETE" });
}

export function terminateSession(id: string, token: string): Promise<void> {
  return apiFetch<void>(
    `/api/users/${id}/sessions/${encodeURIComponent(token)}`,
    { method: "DELETE" },
  );
}

export function resetMfa(userId: string): Promise<{ user: UserRow }> {
  return apiFetch<{ user: UserRow }>(`/api/users/${userId}/reset-mfa`, {
    method: "POST",
  });
}
