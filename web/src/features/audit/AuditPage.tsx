import { useTranslation } from "react-i18next";
import { useState } from "react";
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
              <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
                {t("audit.error.fetch")}
              </div>
            )}
            {list.loading && !list.data ? (
              <div className="rounded-lg border border-border bg-background p-6 text-sm text-muted-foreground">
                Loading...
              </div>
            ) : (
              <AuditTimeline
                data={list.data}
                onSelect={setSelected}
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
          onClose={() => setSelected(null)}
          onActorFilter={(actor) => {
            setSelected(null);
            set({ actor, page: 1 });
          }}
          onTargetFilter={(target) => {
            setSelected(null);
            set({ target_type: target.target_type, target_id: target.target_id, page: 1 });
          }}
          onTargetTypeFilter={(targetType) => {
            setSelected(null);
            set({ target_type: targetType, target_id: undefined, page: 1 });
          }}
          onEventTypeFilter={(eventType) => {
            setSelected(null);
            set({ event_types: [eventType], page: 1 });
          }}
          onOutcomeFilter={(outcome) => {
            setSelected(null);
            set({ outcome, page: 1 });
          }}
        />
      )}
    </>
  );
}
