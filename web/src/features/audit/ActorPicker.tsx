import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { ActorsResponse, AuditState } from "./types";
import { stateToParams } from "./useUrlState";
import { usePickerFetch } from "./usePickerFetch";

function isActorsResponse(body: unknown): body is ActorsResponse {
  if (!body || typeof body !== "object") return false;
  const c = body as { users?: unknown; system_count?: unknown };
  return Array.isArray(c.users);
}

export function ActorPicker({ state, onSelect }: { state: AuditState; onSelect: (actor: string) => void }) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const params = useMemo(() => stateToParams({ ...state, actor: undefined, page: 1 }), [state]);
  const fetched = usePickerFetch<ActorsResponse>("/api/audit/actors", params, { validate: isActorsResponse });
  const data = fetched.data ?? { users: [], system_count: 0 };

  const users = useMemo(() => {
    const needle = query.toLowerCase();
    return (data.users ?? []).filter((user) => user.actor_email.toLowerCase().includes(needle));
  }, [data.users, query]);

  return (
    <div
      id="audit-actor-popover"
      role="dialog"
      aria-label={t("audit.actorPicker.title")}
      className="absolute left-0 top-9 z-30 w-72 rounded-lg border border-border bg-popover p-2 text-popover-foreground shadow-lg"
    >
      <input
        autoFocus
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder={t("audit.actorPicker.search")}
        className="mb-2 h-8 w-full rounded-md border border-border bg-background px-2 text-sm outline-none focus:border-primary/50"
      />
      <div role="listbox" className="max-h-72 overflow-y-auto">
        {data.system_count > 0 && (
          <button type="button" role="option" className="flex w-full items-center justify-between rounded-md px-2 py-2 text-left text-sm hover:bg-muted" onClick={() => onSelect("system")}>
            <span>{t("audit.panel.system")}</span>
            <span className="text-xs text-muted-foreground">{data.system_count}</span>
          </button>
        )}
        {users.map((user) => (
          <button key={user.actor_id} type="button" role="option" className="flex w-full items-center justify-between rounded-md px-2 py-2 text-left text-sm hover:bg-muted" onClick={() => onSelect(user.actor_email)}>
            <span className="truncate">{user.actor_email}</span>
            <span className="ml-3 text-xs text-muted-foreground">{user.count}</span>
          </button>
        ))}
        {users.length === 0 && data.system_count === 0 && !fetched.loading && (
          <div className="px-2 py-6 text-center text-sm text-muted-foreground">{t("audit.actorPicker.empty")}</div>
        )}
      </div>
    </div>
  );
}
