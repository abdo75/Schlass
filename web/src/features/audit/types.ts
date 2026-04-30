export type Outcome = "success" | "failure";

export interface AuditItem {
  id: string;
  event_type: string;
  outcome: Outcome;
  actor_id: string | null;
  actor_email: string | null;
  actor_display: string;
  actor_pseudonymized: boolean;
  target_type: string | null;
  target_id: string | null;
  target_display: string | null;
  client_id: string | null;
  ip_address: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ListResponse {
  items: AuditItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface ActorBucket {
  actor_id: string;
  actor_email: string;
  count: number;
}

export interface ActorsResponse {
  users: ActorBucket[];
  system_count: number;
}

export interface TargetBucket {
  target_type: string;
  target_id: string;
  display: string;
  extra?: string;
}

export interface TargetsResponse {
  items: TargetBucket[];
}

export interface AuditState {
  view: "all" | "sign-in" | "admin" | "client";
  since: string;
  until?: string;
  actor?: string;
  target_type?: string;
  target_id?: string;
  event_types?: string[];
  page: number;
  pageSize: number;
  selectedEventId?: string;
}
