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
