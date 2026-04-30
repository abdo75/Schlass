import { useEffect, useMemo, useState } from "react";
import type { ActorsResponse, AuditState } from "./types";
import { stateToParams } from "./useUrlState";

export function ActorPicker({ state, onSelect }: { state: AuditState; onSelect: (actor: string) => void }) {
  const [query, setQuery] = useState("");
  const [data, setData] = useState<ActorsResponse>({ users: [], system_count: 0 });

  useEffect(() => {
    const controller = new AbortController();
    const params = stateToParams({ ...state, actor: undefined, page: 1 });
    fetch(`/api/audit/actors?${params}`, { signal: controller.signal })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error("actor fetch failed"))))
      .then((body: ActorsResponse) =>
        setData({ users: body.users ?? [], system_count: body.system_count ?? 0 }),
      )
      .catch((err: Error) => {
        if (err.name !== "AbortError") setData({ users: [], system_count: 0 });
      });
    return () => controller.abort();
  }, [state]);

  const users = useMemo(() => {
    const list = data.users ?? [];
    const needle = query.toLowerCase();
    return list.filter((user) => user.actor_email.toLowerCase().includes(needle));
  }, [data.users, query]);

  return (
    <div className="absolute left-0 top-9 z-30 w-72 rounded-lg border border-border bg-popover p-2 text-popover-foreground shadow-lg">
      <input
        autoFocus
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder="Search actors"
        className="mb-2 h-8 w-full rounded-md border border-border bg-background px-2 text-sm outline-none focus:border-primary/50"
      />
      <div role="listbox" className="max-h-72 overflow-y-auto">
        {data.system_count > 0 && (
          <button type="button" role="option" className="flex w-full items-center justify-between rounded-md px-2 py-2 text-left text-sm hover:bg-muted" onClick={() => onSelect("system")}>
            <span>System</span>
            <span className="text-xs text-muted-foreground">{data.system_count}</span>
          </button>
        )}
        {users.map((user) => (
          <button key={user.actor_id} type="button" role="option" className="flex w-full items-center justify-between rounded-md px-2 py-2 text-left text-sm hover:bg-muted" onClick={() => onSelect(user.actor_email)}>
            <span className="truncate">{user.actor_email}</span>
            <span className="ml-3 text-xs text-muted-foreground">{user.count}</span>
          </button>
        ))}
        {users.length === 0 && data.system_count === 0 && <div className="px-2 py-6 text-center text-sm text-muted-foreground">No actors found.</div>}
      </div>
    </div>
  );
}
