import { apiFetch } from "@/lib/api";

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
