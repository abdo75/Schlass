import { apiFetch } from "@/lib/api";

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  force_password_change: boolean;
  force_mfa_enrollment: boolean;
  totp_enrolled_at?: string | null;
  mfa?: { unused_recovery_codes: number };
}

export type LoginResponse =
  | { kind: "session"; user: AuthUser }
  | { kind: "enrollment_required" }
  | { kind: "challenge_required" };

export interface MeResponse {
  user: AuthUser;
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  const data = await apiFetch<{
    user?: AuthUser;
    totp_enrollment_required?: boolean;
    totp_required?: boolean;
  }>("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (data.totp_enrollment_required) return { kind: "enrollment_required" };
  if (data.totp_required) return { kind: "challenge_required" };
  if (data.user) return { kind: "session", user: data.user };
  throw new Error("unexpected login response shape");
}

export function logout(): Promise<void> {
  return apiFetch<void>("/api/logout", { method: "POST" });
}

export function getMe(): Promise<MeResponse> {
  return apiFetch<MeResponse>("/api/me", { method: "GET" });
}

export function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  return apiFetch<void>("/api/change-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}
