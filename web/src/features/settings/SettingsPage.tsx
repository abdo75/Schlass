import { useEffect, useState } from "react";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { getSettings, type SettingsSnapshot } from "./api";
import { friendlyError } from "@/features/clients/errorDisplay";

type TabKey = "general" | "security" | "tokens" | "email";

// SettingsPage is the shell — tabs render stubs in T7. Real tab bodies are
// plugged in by Tasks 8-11 (General, Security, Tokens, Email). Dirty-state
// management + floating save bar are added in T8.
export function SettingsPage() {
  const [snapshot, setSnapshot] = useState<SettingsSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("general");

  useEffect(() => {
    let cancelled = false;
    getSettings()
      .then((snap) => {
        if (!cancelled) setSnapshot(snap);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(friendlyError(err));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const tabs: Array<{ key: TabKey; label: string }> = [
    { key: "general", label: "General" },
    { key: "security", label: "Security" },
    { key: "tokens", label: "Tokens" },
    { key: "email", label: "Email" },
  ];

  return (
    <>
      <AdminPageHeader title="Settings" />
      <AdminPageContent>
        <div className="mx-auto max-w-[720px]">
          {error && (
            <p className="mb-4 text-sm text-destructive" role="alert">
              {error}
            </p>
          )}

          <div className="mb-6 flex gap-0.5 border-b border-border">
            {tabs.map((t) => (
              <button
                key={t.key}
                type="button"
                onClick={() => setActiveTab(t.key)}
                className={
                  "px-4 py-2.5 text-[13.5px] font-medium border-b-2 -mb-px " +
                  (activeTab === t.key
                    ? "text-foreground border-primary"
                    : "text-muted-foreground border-transparent hover:text-foreground")
                }
              >
                {t.label}
              </button>
            ))}
          </div>

          {snapshot === null ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <>
              {activeTab === "general" && <p className="text-sm text-muted-foreground">General tab — plugged in by Task 8.</p>}
              {activeTab === "security" && <p className="text-sm text-muted-foreground">Security tab — plugged in by Task 9.</p>}
              {activeTab === "tokens" && <p className="text-sm text-muted-foreground">Tokens tab — plugged in by Task 10.</p>}
              {activeTab === "email" && <p className="text-sm text-muted-foreground">Email tab — plugged in by Task 11.</p>}
            </>
          )}
        </div>
      </AdminPageContent>
    </>
  );
}
