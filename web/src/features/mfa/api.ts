import { apiFetch } from "@/lib/api";

export interface EnrollmentStartResponse {
  secret_base32: string;
  provision_uri: string;
}

export interface EnrollmentVerifyResponse {
  recovery_codes: string[];
}

export async function startEnrollment(): Promise<EnrollmentStartResponse> {
  return apiFetch<EnrollmentStartResponse>("/api/mfa/enrollment/start", {
    method: "POST",
  });
}

export async function verifyEnrollment(code: string): Promise<EnrollmentVerifyResponse> {
  return apiFetch<EnrollmentVerifyResponse>("/api/mfa/enrollment/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
}

export async function completeEnrollment(): Promise<void> {
  await apiFetch<void>("/api/mfa/enrollment/complete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ acknowledged: true }),
  });
}

export async function submitChallenge(input: { code?: string; recovery_code?: string }): Promise<void> {
  await apiFetch<void>("/api/mfa/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}
