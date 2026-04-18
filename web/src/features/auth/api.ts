import { apiFetch } from "@/lib/api";

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  force_password_change: boolean;
  force_mfa_enrollment: boolean;
  totp_enrolled_at?: string | null;
  last_login_at?: string | null;
  mfa?: { unused_recovery_codes: number };
}

export type LoginResponse =
  | { kind: "session"; user: AuthUser; redirectTo?: string }
  | { kind: "enrollment_required" }
  | { kind: "challenge_required" };

export interface MeResponse {
  user: AuthUser;
}

export interface ChangePasswordResponse {
  redirectTo?: string;
}

export async function login(
  email: string,
  password: string,
  returnTo?: string,
): Promise<LoginResponse> {
  const body: Record<string, string> = { email, password };
  if (returnTo) body.return_to = returnTo;
  const data = await apiFetch<{
    user?: AuthUser;
    totp_enrollment_required?: boolean;
    totp_required?: boolean;
    redirect_to?: string;
  }>("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (data.totp_enrollment_required) return { kind: "enrollment_required" };
  if (data.totp_required) return { kind: "challenge_required" };
  if (data.user) return { kind: "session", user: data.user, redirectTo: data.redirect_to };
  throw new Error("unexpected login response shape");
}

export function logout(): Promise<void> {
  return apiFetch<void>("/api/logout", { method: "POST" });
}

export function getMe(): Promise<MeResponse> {
  return apiFetch<MeResponse>("/api/me", { method: "GET" });
}

export async function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<ChangePasswordResponse> {
  const data = await apiFetch<{ redirect_to?: string }>("/api/change-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  return { redirectTo: data?.redirect_to };
}
