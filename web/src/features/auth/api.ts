import { apiFetch } from "@/lib/api";

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  force_password_change: boolean;
}

export interface LoginResponse {
  user: AuthUser;
}

export interface MeResponse {
  user: AuthUser;
}

export function login(email: string, password: string): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
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
