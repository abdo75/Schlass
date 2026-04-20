import { useCallback, useEffect, useMemo, useState } from "react";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import {
  getSettings,
  patchGeneral,
  patchSecurity,
  patchTokens,
  patchEmail,
  type PatchEmailBody,
  type SettingsSnapshot,
  type SecuritySettings,
  type TokenSettings,
} from "./api";
import { friendlyError } from "@/features/clients/errorDisplay";
import { FloatingSaveBar } from "./FloatingSaveBar";
import { GeneralTab } from "./GeneralTab";
import { SecurityTab } from "./SecurityTab";
import { TokensTab } from "./TokensTab";
import { EmailTab, type EmailTabValue } from "./EmailTab";

type TabKey = "general" | "security" | "tokens" | "email";

// Per-domain dirty buffers. When a field diverges from the server snapshot
// it lives here until the user either discards (clears the buffer) or
// saves (the diff-of-buffer-vs-snapshot is PATCHed, then snapshot reloads
// and the buffer clears). One buffer per domain so T10-T11 can extend this
// without touching the General / Security code paths.
interface Buffer {
  general?: { instance_name?: string };
  security?: Partial<SecuritySettings>;
  tokens?: Partial<TokenSettings>;
  email?: {
    host?: string;
    port?: number;
    username?: string;
    password?: string;
    from?: string;
  };
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

  // Dirty Security keys — only keys whose buffered value diverges from the
  // server snapshot. Just "being in the buffer" is not enough; a switch
  // toggled twice or a NumberInput rebounded to the original value is clean.
  const dirtySecurityKeys = useMemo(() => {
    const s = new Set<keyof SecuritySettings>();
    if (snapshot === null || !buffer.security) return s;
    (Object.keys(buffer.security) as Array<keyof SecuritySettings>).forEach((k) => {
      if (buffer.security![k] !== snapshot.security[k]) s.add(k);
    });
    return s;
  }, [snapshot, buffer.security]);

  // Current Security value = snapshot merged with any buffered overrides.
  // Falls back to inert defaults while snapshot is loading so the tab can
  // still mount without null-guards at every field read.
  const currentSecurity: SecuritySettings = snapshot
    ? { ...snapshot.security, ...(buffer.security ?? {}) }
    : {
        mfa_required: false,
        password_min_length: 12,
        password_require_upper: false,
        password_require_digit: false,
        lockout_threshold: 5,
        lockout_duration_secs: 900,
      };

  // Dirty Token keys — mirror of dirtySecurityKeys.
  const dirtyTokenKeys = useMemo(() => {
    const s = new Set<keyof TokenSettings>();
    if (snapshot === null || !buffer.tokens) return s;
    (Object.keys(buffer.tokens) as Array<keyof TokenSettings>).forEach((k) => {
      if (buffer.tokens![k] !== snapshot.tokens[k]) s.add(k);
    });
    return s;
  }, [snapshot, buffer.tokens]);

  const currentTokens: TokenSettings = snapshot
    ? { ...snapshot.tokens, ...(buffer.tokens ?? {}) }
    : { access_token_ttl_secs: 900, refresh_token_ttl_secs: 86400 };

  // Email current value = snapshot merged with any buffered overrides.
  // The password field is special: an empty string in the buffer means
  // "keep current" — the bullet placeholder is rendered inside EmailTab
  // based on passwordSet, not by pre-populating the buffer here.
  const currentEmail: EmailTabValue = snapshot
    ? {
        host: buffer.email?.host ?? snapshot.email.smtp_host,
        port: buffer.email?.port ?? snapshot.email.smtp_port,
        username: buffer.email?.username ?? snapshot.email.smtp_username,
        password: buffer.email?.password ?? "",
        from: buffer.email?.from ?? snapshot.email.smtp_from,
        passwordSet: snapshot.email.smtp_password_set,
      }
    : { host: "", port: 587, username: "", password: "", from: "", passwordSet: false };

  // Dirty Email count — stricter than the other tabs. Empty password is
  // NOT a change (keep-current semantic), so a buffered empty password
  // contributes 0 to dirty count. Non-empty always counts.
  const dirtyEmailCount = useMemo(() => {
    if (snapshot === null || !buffer.email) return 0;
    let n = 0;
    if (buffer.email.host !== undefined && buffer.email.host !== snapshot.email.smtp_host) n++;
    if (buffer.email.port !== undefined && buffer.email.port !== snapshot.email.smtp_port) n++;
    if (buffer.email.username !== undefined && buffer.email.username !== snapshot.email.smtp_username) n++;
    if (buffer.email.from !== undefined && buffer.email.from !== snapshot.email.smtp_from) n++;
    // Password: only counts as dirty when non-empty (empty = keep current).
    if (buffer.email.password !== undefined && buffer.email.password !== "") n++;
    return n;
  }, [snapshot, buffer.email]);

  // Dirty field count across all tabs.
  const dirtyCount = useMemo(() => {
    if (snapshot === null) return 0;
    let n = 0;
    if (
      buffer.general?.instance_name !== undefined &&
      buffer.general.instance_name !== snapshot.general.instance_name
    )
      n++;
    n += dirtySecurityKeys.size;
    n += dirtyTokenKeys.size;
    n += dirtyEmailCount;
    return n;
  }, [snapshot, buffer, dirtySecurityKeys, dirtyTokenKeys, dirtyEmailCount]);

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
      if (dirtySecurityKeys.size > 0) {
        const payload: Partial<SecuritySettings> = {};
        dirtySecurityKeys.forEach((k) => {
          (payload as Record<string, unknown>)[k] = currentSecurity[k];
        });
        await patchSecurity(payload);
      }
      if (dirtyTokenKeys.size > 0) {
        const payload: Partial<TokenSettings> = {};
        dirtyTokenKeys.forEach((k) => {
          (payload as Record<string, unknown>)[k] = currentTokens[k];
        });
        await patchTokens(payload);
      }
      if (dirtyEmailCount > 0 && buffer.email) {
        const payload: PatchEmailBody = {};
        if (buffer.email.host !== undefined && buffer.email.host !== snapshot.email.smtp_host)
          payload.smtp_host = buffer.email.host;
        if (buffer.email.port !== undefined && buffer.email.port !== snapshot.email.smtp_port)
          payload.smtp_port = buffer.email.port;
        if (buffer.email.username !== undefined && buffer.email.username !== snapshot.email.smtp_username)
          payload.smtp_username = buffer.email.username;
        if (buffer.email.from !== undefined && buffer.email.from !== snapshot.email.smtp_from)
          payload.smtp_from = buffer.email.from;
        // Only include password when non-empty (empty = keep current).
        if (buffer.email.password !== undefined && buffer.email.password !== "")
          payload.smtp_password = buffer.email.password;
        if (Object.keys(payload).length > 0) {
          await patchEmail(payload);
        }
      }
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
      className="relative flex flex-1 flex-col"
      style={{ ["--page-max-w" as string]: "720px", ["--page-gutter" as string]: "32px" }}
    >
      <AdminPageHeader title="Settings" />
      <AdminPageContent>
        <div className="mx-auto w-full flex-1 pb-28" style={{ maxWidth: "var(--page-max-w)" }}>
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
                <SecurityTab
                  value={currentSecurity}
                  onChange={(next) => setBuffer((b) => ({ ...b, security: next }))}
                  dirtyKeys={dirtySecurityKeys}
                />
              )}
              {activeTab === "tokens" && (
                <TokensTab
                  value={currentTokens}
                  onChange={(next) => setBuffer((b) => ({ ...b, tokens: next }))}
                  dirtyKeys={dirtyTokenKeys}
                />
              )}
              {activeTab === "email" && (
                <EmailTab
                  value={currentEmail}
                  onChange={(next) =>
                    setBuffer((b) => ({
                      ...b,
                      email: {
                        host: next.host,
                        port: next.port,
                        username: next.username,
                        password: next.password,
                        from: next.from,
                      },
                    }))
                  }
                  isDirty={dirtyEmailCount > 0}
                />
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
