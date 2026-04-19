import { ApiRequestError } from "@/lib/api";

// friendlyError returns a human-readable message from an unknown error.
// Preference order:
//   1. ApiRequestError.message — backend-supplied, specific (e.g. "At least
//      one redirect_uri is required.", "Only confidential clients are
//      supported.")
//   2. generic fallback
//
// The backend always sets a descriptive message on clients.* validation
// errors (see internal/handler/clients.go), so path 1 is the common case.
// Exposing the backend message directly is the simplest way to give admins
// actionable information instead of opaque error codes.
export function friendlyError(err: unknown): string {
  if (err instanceof ApiRequestError && err.message) {
    return err.message;
  }
  if (err instanceof Error && err.message) {
    return err.message;
  }
  return "An unexpected error occurred.";
}
