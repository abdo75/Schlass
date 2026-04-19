export const ALL_SCOPES = [
  "openid",
  "profile",
  "email",
  "offline_access",
] as const;

export const ALL_GRANTS = [
  "authorization_code",
  "refresh_token",
] as const;

export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: "Required for OIDC. Issues an ID token alongside the access token.",
  profile: "User's display name, preferred username, and locale.",
  email: "User's email address and verification status.",
  offline_access:
    "Required to issue refresh tokens. Enables long-lived sessions.",
};

export const GRANT_DESCRIPTIONS: Record<string, string> = {
  authorization_code: "Standard browser-based OIDC flow with PKCE.",
  refresh_token: "Rotates on every use. Requires the offline_access scope.",
};

export function relativeTime(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
