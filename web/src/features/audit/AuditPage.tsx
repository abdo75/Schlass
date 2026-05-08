import { useTranslation } from "react-i18next";
import { useEffect, useState } from "react";
import { AdminPageContent, AdminPageHeader } from "@/components/AdminLayout";
import { Pagination } from "@/components/Pagination";
import { AuditPanel } from "./AuditPanel";
import { AuditFilterBar } from "./AuditFilterBar";
import { AuditTabs, AUDIT_TABPANEL_ID } from "./AuditTabs";
import { AuditTimeline } from "./AuditTimeline";
import { ExportMenu } from "./ExportMenu";
import { useAuditList } from "./useAuditQuery";
import { useUrlState } from "./useUrlState";
import type { AuditItem } from "./types";

export function AuditPage() {
  const { t } = useTranslation();
  const { state, set } = useUrlState();
  const list = useAuditList(state);
  const [selected, setSelected] = useState<AuditItem | null>(null);

  // Hydrate the panel from a deep-link (?event=<id>) once the list arrives.
  // Effect-based setState here is intentional: the list is fetched async, so
  // we cannot derive `selected` from props alone.
  useEffect(() => {
    if (!state.selectedEventId || !list.data || selected) return;
    const found = list.data.items.find((item) => item.id === state.selectedEventId);
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (found) setSelected(found);
  }, [state.selectedEventId, list.data, selected]);

  function openEvent(item: AuditItem) {
    setSelected(item);
    if (state.selectedEventId !== item.id) set({ selectedEventId: item.id });
  }

  function closeEvent() {
    setSelected(null);
    if (state.selectedEventId) set({ selectedEventId: undefined });
  }

  return (
    <>
      <AdminPageHeader
        title={t("audit.title")}
        subtitle={t("audit.subtitle")}
        primaryAction={<ExportMenu state={state} />}
      />
      <AdminPageContent>
        <div data-testid="audit-page" className="space-y-4">
          <AuditTabs state={state} onChange={set} />
          <div id={AUDIT_TABPANEL_ID} role="tabpanel" aria-labelledby={`audit-tab-${state.view}`}>
            <AuditFilterBar state={state} onChange={set} />
            {list.error && (
              <div className="flex items-center justify-between gap-3 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
                <span>{t("audit.error.fetch")}</span>
                <button
                  type="button"
                  className="rounded-md border border-destructive/30 bg-background px-2 py-1 text-xs font-medium hover:bg-muted"
                  onClick={list.retry}
                >
                  {t("audit.error.retry")}
                </button>
              </div>
            )}
            {list.loading && !list.data ? (
              <div className="rounded-lg border border-border bg-background p-6 text-sm text-muted-foreground">
                {t("audit.loading")}
              </div>
            ) : (
              <AuditTimeline
                data={list.data}
                onSelect={openEvent}
                onActorFilter={(actor) => set({ actor, page: 1 })}
                onEventTypeFilter={(eventType) => set({ event_types: [eventType], page: 1 })}
                onOutcomeFilter={(outcome) => set({ outcome, page: 1 })}
              />
            )}
            <Pagination
              totalCount={list.data?.total ?? 0}
              totalPages={Math.max(1, Math.ceil((list.data?.total ?? 0) / state.pageSize))}
              pageSize={state.pageSize}
              currentPage={state.page}
              onPageChange={(page) => set({ page })}
            />
          </div>
        </div>
      </AdminPageContent>
      {selected && (
        <AuditPanel
          event={selected}
          onClose={closeEvent}
          onActorFilter={(actor) => {
            closeEvent();
            set({ actor, page: 1 });
          }}
          onTargetFilter={(target) => {
            closeEvent();
            set({ target_type: target.target_type, target_id: target.target_id, page: 1 });
          }}
          onTargetTypeFilter={(targetType) => {
            closeEvent();
            set({ target_type: targetType, target_id: undefined, page: 1 });
          }}
          onEventTypeFilter={(eventType) => {
            closeEvent();
            set({ event_types: [eventType], page: 1 });
          }}
          onOutcomeFilter={(outcome) => {
            closeEvent();
            set({ outcome, page: 1 });
          }}
        />
      )}
    </>
  );
}
