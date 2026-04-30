import { describe, expect, it } from "vitest";
import { EVENT_TYPES_KNOWN, lookupAlert, lookupHint, lookupReason, renderSentence, severity } from "./catalog";

describe("catalog", () => {
  it("renders a non-fallback sentence for every known event type", () => {
    for (const eventType of EVENT_TYPES_KNOWN) {
      const out = renderSentence(eventType, mockMetadata(eventType), "alice@example.com", "Grafana");
      expect(out.text.length, eventType).toBeGreaterThan(0);
      expect(out.fallback, eventType).toBe(false);
    }
  });

  it("classifies critical events as critical", () => {
    expect(severity("oidc.refresh.reuse_detected", {})).toBe("critical");
    expect(severity("client.secret_rotated", {})).toBe("critical");
    expect(severity("login.succeeded", {})).toBe("normal");
  });

  it("decodes login.failed reasons", () => {
    expect(lookupReason("login.failed", { reason: "wrong_password" }).key).toBe("audit.reason.login.wrong_password");
    expect(lookupReason("login.failed", { reason: "wrong_password" }).fallback).toBe(false);
  });

  it("falls back when reason is unknown", () => {
    const r = lookupReason("login.failed", { reason: "moonbeam_invalid" });
    expect(r.fallback).toBe(true);
    expect(r.raw).toBe("moonbeam_invalid");
  });

  it("decodes oidc.authorize.invalid_request via oauth_error", () => {
    const r = lookupReason("oidc.authorize.invalid_request", { oauth_error: "invalid_scope", reason: "scope foo not allowed" });
    expect(r.key).toBe("audit.reason.oidcAuthorizeInvalidRequest.invalid_scope");
    expect(r.secondary).toBe("scope foo not allowed");
  });

  it("returns alert key for security events only", () => {
    expect(lookupAlert("oidc.refresh.reuse_detected")).toBe("audit.alert.oidc.refresh.reuse_detected");
    expect(lookupAlert("login.succeeded")).toBeNull();
  });

  it("returns hint with direction", () => {
    expect(lookupHint("access_token_ttl_secs", 600, 900).key).toBe("audit.hint.access_token_ttl_secs.up");
  });
});

function mockMetadata(eventType: string): Record<string, unknown> {
  if (eventType === "audit.exported") return { format: "csv", row_count: 5 };
  return {};
}
