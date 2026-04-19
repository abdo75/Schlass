import { apiFetch } from "@/lib/api";

export type ClientStatus = "active" | "disabled";

export interface ClientDTO {
  id: string;
  name: string;
  client_type: "confidential" | "public";
  redirect_uris: string[];
  allowed_grant_types: string[];
  allowed_scopes: string[];
  token_endpoint_auth_method: string;
  status: ClientStatus;
  disabled_at?: string | null;
  created_by_user_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateClientRequest {
  name: string;
  client_type: "confidential";
  redirect_uris: string[];
  allowed_grant_types: string[];
  allowed_scopes: string[];
}

export interface CreateClientResponse {
  client_id: string;
  client_secret: string;
  client: ClientDTO;
}

export interface RotateSecretResponse {
  client_id: string;
  client_secret: string;
  previous_secret_expires_at: string;
}

export interface UpdateClientRequest {
  name?: string;
  redirect_uris?: string[];
  allowed_scopes?: string[];
  allowed_grant_types?: string[];
}

export function listClients(status: "active" | "disabled" | "all" = "active") {
  return apiFetch<{ clients: ClientDTO[] }>(`/api/clients?status=${status}`);
}

export function getClient(id: string) {
  return apiFetch<{ client: ClientDTO }>(`/api/clients/${id}`);
}

export function createClient(req: CreateClientRequest) {
  return apiFetch<CreateClientResponse>(`/api/clients`, {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export function updateClient(id: string, req: UpdateClientRequest) {
  return apiFetch<{ client: ClientDTO }>(`/api/clients/${id}`, {
    method: "PATCH",
    body: JSON.stringify(req),
  });
}

export function disableClient(id: string) {
  return apiFetch<void>(`/api/clients/${id}/disable`, { method: "POST" });
}

export function enableClient(id: string) {
  return apiFetch<void>(`/api/clients/${id}/enable`, { method: "POST" });
}

export function rotateClientSecret(id: string) {
  return apiFetch<RotateSecretResponse>(`/api/clients/${id}/rotate-secret`, {
    method: "POST",
  });
}

export function deleteClient(id: string) {
  return apiFetch<void>(`/api/clients/${id}`, { method: "DELETE" });
}

// Signing keys — admin rotate endpoint already exists from Sprint 4.
export function rotateSigningKey() {
  return apiFetch<void>(`/api/admin/signing-keys/rotate`, {
    method: "POST",
  });
}

// SigningKey mirrors the admin /api/admin/signing-keys list payload.
// Unlike JWKS (which is public and omits status/timestamps), this admin
// endpoint carries the metadata the UI needs to label keys active vs
// retiring and to compute the retirement countdown.
export interface SigningKey {
  kid: string;
  algorithm: string;
  status: "active" | "retiring";
  created_at: string;
  rotated_at: string | null;
}

export function listSigningKeys() {
  return apiFetch<{ keys: SigningKey[] }>("/api/admin/signing-keys");
}

// emergencyRetireSigningKey transitions a retiring key to retired
// immediately, removing it from JWKS. Break-glass for suspected key
// compromise — prefer the normal rotation path for routine lifecycle.
export function emergencyRetireSigningKey(kid: string) {
  return apiFetch<void>(`/api/admin/signing-keys/${encodeURIComponent(kid)}/retire-now`, {
    method: "POST",
  });
}
