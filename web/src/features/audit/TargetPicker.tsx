import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { PickerSkeleton } from "./PickerSkeleton";
import type { AuditState, TargetsResponse } from "./types";
import { stateToParams } from "./useUrlState";
import { usePickerFetch } from "./usePickerFetch";

const TARGET_TYPES = ["user", "client", "system"] as const;

export type TargetSelection = {
  target_type: string;
  target_id: string;
  display?: string;
};

function isTargetsResponse(body: unknown): body is TargetsResponse {
  if (!body || typeof body !== "object") return false;
  return Array.isArray((body as { items?: unknown }).items);
}

export function TargetPicker({ state, onSelect }: { state: AuditState; onSelect: (target: TargetSelection) => void }) {
  const { t } = useTranslation();
  const [type, setType] = useState<string | null>(state.target_type ?? null);
  const [query, setQuery] = useState("");

  const params = useMemo(() => {
    const p = stateToParams({ ...state, target_type: undefined, target_id: undefined, page: 1 });
    if (type) p.set("type", type);
    return p;
  }, [state, type]);

  const fetched = usePickerFetch<TargetsResponse>("/api/audit/targets", params, {
    skip: !type,
    validate: isTargetsResponse,
  });

  const filtered = useMemo(() => {
    const items = fetched.data?.items ?? [];
    const needle = query.toLowerCase();
    return items.filter((item) => `${item.display} ${item.target_id} ${item.extra ?? ""}`.toLowerCase().includes(needle));
  }, [fetched.data, query]);

  return (
    <div
      id="audit-target-popover"
      role="dialog"
      aria-label={t("audit.targetPicker.title")}
      className="absolute left-0 top-9 z-30 w-80 rounded-lg border border-border bg-popover p-2 text-popover-foreground shadow-lg"
    >
      {!type ? (
        <div role="listbox" aria-label={t("audit.targetPicker.typeAria")} className="grid gap-1">
          {TARGET_TYPES.map((targetType) => (
            <button key={targetType} type="button" role="option" className="rounded-md px-2 py-2 text-left text-sm hover:bg-muted" onClick={() => setType(targetType)}>
              {t(`audit.targetPicker.types.${targetType}`, { defaultValue: targetType })}
            </button>
          ))}
        </div>
      ) : (
        <>
          <div className="mb-2 flex items-center gap-2">
            <button type="button" className="rounded-md px-2 py-1 text-xs text-muted-foreground hover:bg-muted" onClick={() => setType(null)}>{t("audit.targetPicker.back")}</button>
            <span className="text-xs font-semibold uppercase tracking-[0.06em] text-muted-foreground">{t(`audit.targetPicker.types.${type}`, { defaultValue: type })}</span>
          </div>
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("audit.targetPicker.search")}
            className="mb-2 h-8 w-full rounded-md border border-border bg-background px-2 text-sm outline-none focus:border-primary/50"
          />
          <div role="listbox" className="max-h-72 overflow-y-auto">
            {fetched.loading && !fetched.data && <PickerSkeleton />}
            {fetched.error && (
              <div className="flex items-center justify-between gap-2 px-2 py-2 text-sm">
                <span className="text-muted-foreground">{t("audit.error.fetch")}</span>
                <button
                  type="button"
                  className="rounded-md border border-border bg-background px-2 py-1 text-xs font-medium hover:bg-muted"
                  onClick={fetched.retry}
                >
                  {t("audit.error.retry")}
                </button>
              </div>
            )}
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
            {filtered.length === 0 && !fetched.loading && (
              <div className="px-2 py-6 text-center text-sm text-muted-foreground">{t("audit.targetPicker.empty")}</div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
