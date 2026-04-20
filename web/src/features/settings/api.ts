import { apiFetch } from "@/lib/api";

export interface GeneralSettings {
  instance_name: string;
}

export interface SecuritySettings {
  mfa_required: boolean;
  password_min_length: number;
  password_require_upper: boolean;
  password_require_digit: boolean;
  lockout_threshold: number;
  lockout_duration_secs: number;
}

export interface TokenSettings {
  access_token_ttl_secs: number;
  refresh_token_ttl_secs: number;
}

export interface EmailSettings {
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  smtp_password_set: boolean;
  smtp_from: string;
}

export interface SettingsSnapshot {
  general: GeneralSettings;
  security: SecuritySettings;
  tokens: TokenSettings;
  email: EmailSettings;
}

export function getSettings() {
  return apiFetch<SettingsSnapshot>("/api/settings");
}

export function patchGeneral(body: Partial<GeneralSettings>) {
  return apiFetch<GeneralSettings>("/api/settings/general", {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function patchSecurity(body: Partial<SecuritySettings>) {
  return apiFetch<SecuritySettings>("/api/settings/security", {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function patchTokens(body: Partial<TokenSettings>) {
  return apiFetch<TokenSettings>("/api/settings/tokens", {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export interface PatchEmailBody {
  smtp_host?: string;
  smtp_port?: number;
  smtp_username?: string;
  // Empty string = keep current; non-empty = replace. See spec §M4
  // "password field UX".
  smtp_password?: string;
  smtp_from?: string;
}

export function patchEmail(body: PatchEmailBody) {
  return apiFetch<EmailSettings>("/api/settings/email", {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function testEmailConnection() {
  return apiFetch<{ delivered_at: string }>("/api/settings/email/test", {
    method: "POST",
  });
}
