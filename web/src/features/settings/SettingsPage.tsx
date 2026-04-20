import { useCallback, useEffect, useMemo, useState } from "react";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { getSettings, patchGeneral, type SettingsSnapshot } from "./api";
import { friendlyError } from "@/features/clients/errorDisplay";
import { FloatingSaveBar } from "./FloatingSaveBar";
import { GeneralTab } from "./GeneralTab";

type TabKey = "general" | "security" | "tokens" | "email";

// Per-domain dirty buffers. When a field diverges from the server snapshot
// it lives here until the user either discards (clears the buffer) or
// saves (the diff-of-buffer-vs-snapshot is PATCHed, then snapshot reloads
// and the buffer clears). One buffer per domain so T9-T11 can extend this
// without touching the General code path.
interface Buffer {
  general?: { instance_name?: string };
  // security / tokens / email plugged in T9-T11.
}

export function SettingsPage() {
  const [snapshot, setSnapshot] = useState<SettingsSnapshot | null>(null);
  const [buffer, setBuffer] = useState<Buffer>({});
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<TabKey>("general");

  const load = useCallback(async () => {
    setError(null);
    try {
      const snap = await getSettings();
      setSnapshot(snap);
      setBuffer({});
    } catch (err: unknown) {
      setError(friendlyError(err));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const snap = await getSettings();
        if (!cancelled) {
          setSnapshot(snap);
          setBuffer({});
        }
      } catch (err: unknown) {
        if (!cancelled) setError(friendlyError(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Dirty field count across all tabs.
  const dirtyCount = useMemo(() => {
    if (snapshot === null) return 0;
    let n = 0;
    if (
      buffer.general?.instance_name !== undefined &&
      buffer.general.instance_name !== snapshot.general.instance_name
    )
      n++;
    // T9-T11 will add security / tokens / email counts here.
    return n;
  }, [snapshot, buffer]);

  async function handleSave() {
    if (snapshot === null || dirtyCount === 0) return;
    setSaving(true);
    setError(null);
    try {
      if (
        buffer.general?.instance_name !== undefined &&
        buffer.general.instance_name !== snapshot.general.instance_name
      ) {
        await patchGeneral({ instance_name: buffer.general.instance_name });
      }
      // T9-T11 will add security / tokens / email saves here.
      await load();
    } catch (err: unknown) {
      setError(friendlyError(err));
    } finally {
      setSaving(false);
    }
  }

  function handleDiscard() {
    setBuffer({});
  }

  const tabs: Array<{ key: TabKey; label: string }> = [
    { key: "general", label: "General" },
    { key: "security", label: "Security" },
    { key: "tokens", label: "Tokens" },
    { key: "email", label: "Email" },
  ];

  const currentGeneral = buffer.general?.instance_name ?? snapshot?.general.instance_name ?? "";
  const generalDirty =
    buffer.general?.instance_name !== undefined &&
    snapshot !== null &&
    buffer.general.instance_name !== snapshot.general.instance_name;

  return (
    <div
      className="relative"
      style={{ ["--page-max-w" as string]: "720px", ["--page-gutter" as string]: "32px" }}
    >
      <AdminPageHeader title="Settings" />
      <AdminPageContent>
        <div className="mx-auto pb-28" style={{ maxWidth: "var(--page-max-w)" }}>
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
              {activeTab === "general" && (
                <GeneralTab
                  value={currentGeneral}
                  onChange={(next) =>
                    setBuffer((b) => ({ ...b, general: { ...b.general, instance_name: next } }))
                  }
                  dirty={generalDirty}
                />
              )}
              {activeTab === "security" && (
                <p className="text-sm text-muted-foreground">Security tab — plugged in by Task 9.</p>
              )}
              {activeTab === "tokens" && (
                <p className="text-sm text-muted-foreground">Tokens tab — plugged in by Task 10.</p>
              )}
              {activeTab === "email" && (
                <p className="text-sm text-muted-foreground">Email tab — plugged in by Task 11.</p>
              )}
            </>
          )}
        </div>
      </AdminPageContent>

      <FloatingSaveBar
        dirtyCount={dirtyCount}
        onSave={() => void handleSave()}
        onDiscard={handleDiscard}
        saving={saving}
      />
    </div>
  );
}
