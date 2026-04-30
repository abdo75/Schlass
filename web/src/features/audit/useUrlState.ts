import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { AuditState } from "./types";

export function useUrlState(): { state: AuditState; set: (patch: Partial<AuditState>) => void } {
  const [params, setParams] = useSearchParams();
  const state = useMemo<AuditState>(() => ({
    view: (params.get("view") as AuditState["view"]) ?? "all",
    since: params.get("since") ?? "24h",
    until: params.get("until") ?? undefined,
    actor: params.get("actor") ?? undefined,
    target_type: params.get("target_type") ?? undefined,
    target_id: params.get("target_id") ?? undefined,
    event_types: params.get("event_types")?.split(",").filter(Boolean),
    page: Number.parseInt(params.get("page") ?? "1", 10),
    pageSize: Number.parseInt(params.get("page_size") ?? "25", 10),
    selectedEventId: params.get("event") ?? undefined,
  }), [params]);

  const set = useCallback((patch: Partial<AuditState>) => {
    const next = { ...state, ...patch };
    const out = new URLSearchParams();
    if (next.view !== "all") out.set("view", next.view);
    if (next.since !== "24h") out.set("since", next.since);
    if (next.until) out.set("until", next.until);
    if (next.actor) out.set("actor", next.actor);
    if (next.target_type) out.set("target_type", next.target_type);
    if (next.target_id) out.set("target_id", next.target_id);
    if (next.event_types?.length) out.set("event_types", next.event_types.join(","));
    if (next.page !== 1) out.set("page", String(next.page));
    if (next.pageSize !== 25) out.set("page_size", String(next.pageSize));
    if (next.selectedEventId) out.set("event", next.selectedEventId);
    setParams(out, { replace: false });
  }, [setParams, state]);

  return { state, set };
}

export function stateToParams(state: AuditState): URLSearchParams {
  const p = new URLSearchParams();
  p.set("view", state.view);
  p.set("since", state.since);
  if (state.until) p.set("until", state.until);
  if (state.actor) p.set("actor", state.actor);
  if (state.target_type) p.set("target_type", state.target_type);
  if (state.target_id) p.set("target_id", state.target_id);
  if (state.event_types?.length) p.set("event_types", state.event_types.join(","));
  p.set("page", String(state.page));
  p.set("page_size", String(state.pageSize));
  return p;
}
