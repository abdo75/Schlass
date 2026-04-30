import type { AuditState } from "./types";

const tabs: Array<{ view: AuditState["view"]; label: string }> = [
  { view: "all", label: "All events" },
  { view: "sign-in", label: "Sign-in activity" },
  { view: "admin", label: "Admin actions" },
  { view: "client", label: "Client changes" },
];

export function AuditTabs({ state, onChange }: { state: AuditState; onChange: (patch: Partial<AuditState>) => void }) {
  return (
    <div className="mb-4 flex gap-2" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.view}
          role="tab"
          aria-selected={state.view === tab.view}
          data-testid={`audit-tab-${tab.view}`}
          className={`rounded-md px-3 py-1.5 text-sm font-semibold ${state.view === tab.view ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:bg-muted"}`}
          onClick={() => onChange({ view: tab.view, page: 1 })}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
