import type { AuditState } from "./types";

const tabs: Array<{ view: AuditState["view"]; label: string }> = [
  { view: "all", label: "All events" },
  { view: "sign-in", label: "Sign-in activity" },
  { view: "admin", label: "Admin actions" },
  { view: "client", label: "Client changes" },
];

export function AuditTabs({ state, onChange }: { state: AuditState; onChange: (patch: Partial<AuditState>) => void }) {
  return (
    <div className="mb-6 flex gap-0.5 border-b border-border" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.view}
          type="button"
          role="tab"
          aria-selected={state.view === tab.view}
          data-testid={`audit-tab-${tab.view}`}
          className={
            "px-4 py-2.5 text-[13.5px] font-medium border-b-2 -mb-px " +
            (state.view === tab.view
              ? "text-foreground border-primary"
              : "text-muted-foreground border-transparent hover:text-foreground")
          }
          onClick={() => onChange({ view: tab.view, page: 1 })}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
