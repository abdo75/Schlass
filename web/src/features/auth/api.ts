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

// Backend always returns 200 with empty body regardless of whether email
// matched a user (enumeration-safe). Void return on success.
export function requestPasswordReset(email: string) {
  return apiFetch<void>("/api/password-reset/request", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}

// Confirm returns { user_id } on success. Errors: INVALID_TOKEN (unknown/
// expired/reused) or PASSWORD_POLICY_VIOLATION (policy failure).
export function confirmPasswordReset(token: string, password: string) {
  return apiFetch<{ user_id: string }>("/api/password-reset/confirm", {
    method: "POST",
    body: JSON.stringify({ token, password }),
  });
}

// validateResetToken pings the backend /validate endpoint — read-only
// token check on page mount, so the reset form only renders after the
// token is confirmed valid. Throws an apiFetch error (code =
// "INVALID_TOKEN") on expired / used / unknown tokens.
export function validateResetToken(token: string) {
  return apiFetch<Record<string, never>>("/api/password-reset/validate", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}
