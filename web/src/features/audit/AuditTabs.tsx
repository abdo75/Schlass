import { useRef } from "react";
import { useTranslation } from "react-i18next";
import type { AuditState } from "./types";

const tabs: Array<{ view: AuditState["view"]; labelKey: string }> = [
  { view: "all", labelKey: "audit.tabs.all" },
  { view: "sign-in", labelKey: "audit.tabs.signIn" },
  { view: "admin", labelKey: "audit.tabs.admin" },
  { view: "client", labelKey: "audit.tabs.client" },
];

export const AUDIT_TABPANEL_ID = "audit-tabpanel";

function tabId(view: AuditState["view"]): string {
  return `audit-tab-${view}`;
}

export function AuditTabs({ state, onChange }: { state: AuditState; onChange: (patch: Partial<AuditState>) => void }) {
  const { t } = useTranslation();
  const refs = useRef(new Map<AuditState["view"], HTMLButtonElement>());

  function focusTab(view: AuditState["view"]) {
    refs.current.get(view)?.focus();
    onChange({ view, page: 1 });
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    const idx = tabs.findIndex((tab) => tab.view === state.view);
    if (idx < 0) return;
    switch (event.key) {
      case "ArrowRight": {
        event.preventDefault();
        focusTab(tabs[(idx + 1) % tabs.length].view);
        break;
      }
      case "ArrowLeft": {
        event.preventDefault();
        focusTab(tabs[(idx - 1 + tabs.length) % tabs.length].view);
        break;
      }
      case "Home": {
        event.preventDefault();
        focusTab(tabs[0].view);
        break;
      }
      case "End": {
        event.preventDefault();
        focusTab(tabs[tabs.length - 1].view);
        break;
      }
    }
  }

  return (
    <div
      className="mb-6 flex gap-0.5 border-b border-border"
      role="tablist"
      aria-orientation="horizontal"
      aria-label={t("audit.tabs.ariaLabel")}
      onKeyDown={onKeyDown}
    >
      {tabs.map((tab) => {
        const isActive = state.view === tab.view;
        return (
          <button
            key={tab.view}
            ref={(node) => {
              if (node) refs.current.set(tab.view, node);
              else refs.current.delete(tab.view);
            }}
            id={tabId(tab.view)}
            type="button"
            role="tab"
            aria-selected={isActive}
            aria-controls={AUDIT_TABPANEL_ID}
            tabIndex={isActive ? 0 : -1}
            data-testid={`audit-tab-${tab.view}`}
            className={
              "px-4 py-2.5 text-[13.5px] font-medium border-b-2 -mb-px focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring " +
              (isActive
                ? "text-foreground border-primary"
                : "text-muted-foreground border-transparent hover:text-foreground")
            }
            onClick={() => onChange({ view: tab.view, page: 1 })}
          >
            {t(tab.labelKey)}
          </button>
        );
      })}
    </div>
  );
}
