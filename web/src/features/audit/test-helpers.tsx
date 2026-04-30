import type { AuditItem } from "./types";

export function fakeEvent(overrides: Partial<AuditItem> = {}): AuditItem {
  return {
    id: "evt-1",
    event_type: "login.succeeded",
    outcome: "success",
    actor_id: "user-1",
    actor_email: "alice@example.com",
    actor_display: "alice@example.com",
    actor_pseudonymized: false,
    target_type: "client",
    target_id: "client-1",
    target_display: "Grafana",
    client_id: "client-1",
    ip_address: "127.0.0.1",
    metadata: {},
    created_at: new Date().toISOString(),
    ...overrides,
  };
}
