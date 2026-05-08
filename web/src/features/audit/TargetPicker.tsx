import { useEffect, useMemo, useState } from "react";
import type { AuditState, TargetBucket, TargetsResponse } from "./types";
import { stateToParams } from "./useUrlState";

const TARGET_TYPES = ["user", "client", "system"] as const;

const TYPE_LABELS: Record<string, string> = {
  user: "User",
  client: "Client",
  system: "System",
};

export type TargetSelection = {
  target_type: string;
  target_id: string;
  display?: string;
};

export function TargetPicker({ state, onSelect }: { state: AuditState; onSelect: (target: TargetSelection) => void }) {
  const [type, setType] = useState<string | null>(state.target_type ?? null);
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<TargetBucket[]>([]);

  useEffect(() => {
    if (!type) return;
    const controller = new AbortController();
    const params = stateToParams({ ...state, target_type: undefined, target_id: undefined, page: 1 });
    params.set("type", type);
    fetch(`/api/audit/targets?${params}`, { signal: controller.signal })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error("target fetch failed"))))
      .then((body: TargetsResponse) => setItems(body.items ?? []))
      .catch((err: Error) => {
        if (err.name !== "AbortError") setItems([]);
      });
    return () => controller.abort();
  }, [state, type]);

  const filtered = useMemo(() => {
    const needle = query.toLowerCase();
    return (items ?? []).filter((item) => `${item.display} ${item.target_id} ${item.extra ?? ""}`.toLowerCase().includes(needle));
  }, [items, query]);

  return (
    <div
      id="audit-target-popover"
      role="dialog"
      aria-label="Target"
      className="absolute left-0 top-9 z-30 w-80 rounded-lg border border-border bg-popover p-2 text-popover-foreground shadow-lg"
    >
      {!type ? (
        <div role="listbox" aria-label="Target type" className="grid gap-1">
          {TARGET_TYPES.map((targetType) => (
            <button key={targetType} type="button" role="option" className="rounded-md px-2 py-2 text-left text-sm hover:bg-muted" onClick={() => setType(targetType)}>
              {TYPE_LABELS[targetType] ?? targetType}
            </button>
          ))}
        </div>
      ) : (
        <>
          <div className="mb-2 flex items-center gap-2">
            <button type="button" className="rounded-md px-2 py-1 text-xs text-muted-foreground hover:bg-muted" onClick={() => setType(null)}>Back</button>
            <span className="text-xs font-semibold uppercase tracking-[0.06em] text-muted-foreground">{TYPE_LABELS[type] ?? type}</span>
          </div>
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search targets"
            className="mb-2 h-8 w-full rounded-md border border-border bg-background px-2 text-sm outline-none focus:border-primary/50"
          />
          <div role="listbox" className="max-h-72 overflow-y-auto">
            {filtered.map((item) => (
              <button
                key={`${item.target_type ?? type}:${item.target_id}`}
                type="button"
                role="option"
                className="flex w-full items-center justify-between gap-3 rounded-md px-2 py-2 text-left text-sm hover:bg-muted"
                onClick={() => onSelect({ target_type: item.target_type ?? type, target_id: item.target_id, display: item.display })}
              >
                <span className="truncate">{item.display}</span>
                {item.extra && <span className="text-xs text-muted-foreground">{item.extra}</span>}
              </button>
            ))}
            {filtered.length === 0 && <div className="px-2 py-6 text-center text-sm text-muted-foreground">No targets found.</div>}
          </div>
        </>
      )}
    </div>
  );
}
