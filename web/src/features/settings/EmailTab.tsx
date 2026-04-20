import { useState } from "react";
import { NumberInput } from "@/components/ui/NumberInput";
import { testEmailConnection } from "./api";

// PendingValue holds the admin's in-progress edits for the Email tab.
// password semantics: empty string = "keep current"; non-empty = replace.
// passwordSet comes from the server snapshot and signals whether the
// password placeholder dots should render on mount.
export interface EmailTabValue {
  host: string;
  port: number;
  username: string;
  password: string;
  from: string;
  passwordSet: boolean;
}

interface Props {
  value: EmailTabValue;
  onChange: (next: EmailTabValue) => void;
  // isDirty=true disables the Test Connection button with a "Save before
  // testing" tooltip — backend tests against saved config, not UI state.
  isDirty: boolean;
}

const PASSWORD_PLACEHOLDER = "xxxxxxxxxxxxxxxx";

export function EmailTab({ value, onChange, isDirty }: Props) {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<
    { kind: "ok" | "err"; text: string } | null
  >(null);

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testEmailConnection();
      const when = new Date(res.delivered_at).toLocaleTimeString();
      setTestResult({ kind: "ok", text: `Delivered at ${when}` });
    } catch (err) {
      const msg =
        err && typeof err === "object" && "message" in err
          ? String((err as { message: unknown }).message)
          : "Send failed";
      setTestResult({ kind: "err", text: msg });
    } finally {
      setTesting(false);
    }
  }

  // Password display: when nothing typed yet AND a password is set on the
  // server, show 16 bullet placeholder chars. Click selects them all; any
  // keystroke replaces in one motion.
  const displayPassword =
    value.password === "" && value.passwordSet ? PASSWORD_PLACEHOLDER : value.password;

  return (
    <div className="mb-4 rounded-xl border border-border bg-background overflow-hidden">
      <div className="px-6 pt-5 pb-4 grid grid-cols-[1fr_auto] gap-5 items-start">
        <div>
          <h3 className="text-[15px] font-semibold">SMTP server</h3>
          <p className="mt-1 text-[13px] text-muted-foreground leading-relaxed">
            Outbound mail provider for password reset emails and transactional notifications.
          </p>
          {testResult && (
            <p className="mt-2.5 text-[12.5px] flex items-center gap-2" role="status">
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{
                  background:
                    testResult.kind === "ok" ? "oklch(0.65 0.15 155)" : "var(--destructive)",
                }}
                aria-hidden="true"
              />
              {testResult.text}
            </p>
          )}
        </div>
        <div>
          <button
            type="button"
            onClick={() => void handleTest()}
            disabled={testing || isDirty}
            title={isDirty ? "Save before testing" : undefined}
            className="h-8 border border-border rounded-md px-3.5 text-[13px] font-medium bg-transparent text-foreground hover:bg-muted hover:border-muted-foreground/30 disabled:opacity-50 disabled:cursor-not-allowed inline-flex items-center gap-2"
          >
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="w-3.5 h-3.5"
            >
              <path d="M22 2 11 13" />
              <path d="m22 2-7 20-4-9-9-4Z" />
            </svg>
            {testing ? "Testing…" : "Test connection"}
          </button>
        </div>
      </div>

      <div className="px-6 pt-5 pb-6 border-t border-muted/50 flex flex-col gap-4">
        <div className="grid grid-cols-[1fr_120px] gap-3 items-start">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="smtp-host" className="text-[13px] font-medium">
              Host
            </label>
            <input
              id="smtp-host"
              type="text"
              value={value.host}
              onChange={(e) => onChange({ ...value, host: e.target.value })}
              placeholder="smtp.example.com"
              className="h-[34px] border border-border rounded-md px-3 text-[13.5px] bg-background focus:outline-0 focus:border-primary focus:ring-2 focus:ring-primary/20"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="smtp-port" className="text-[13px] font-medium">
              Port
            </label>
            <NumberInput
              value={value.port || 587}
              min={1}
              max={65535}
              ariaLabel="Port"
              onChange={(n) => onChange({ ...value, port: n })}
              className="!w-full"
            />
          </div>
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="smtp-user" className="text-[13px] font-medium">
            Username
          </label>
          <input
            id="smtp-user"
            type="text"
            value={value.username}
            onChange={(e) => onChange({ ...value, username: e.target.value })}
            className="h-[34px] border border-border rounded-md px-3 text-[13.5px] bg-background focus:outline-0 focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="smtp-pw" className="text-[13px] font-medium">
            Password
          </label>
          <input
            id="smtp-pw"
            type="password"
            autoComplete="new-password"
            value={displayPassword}
            onChange={(e) => onChange({ ...value, password: e.target.value })}
            onFocus={(e) => {
              if (e.target.value === PASSWORD_PLACEHOLDER) e.target.select();
            }}
            className="h-[34px] border border-border rounded-md px-3 text-[13.5px] bg-background focus:outline-0 focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <label htmlFor="smtp-from" className="text-[13px] font-medium">
            From address
          </label>
          <input
            id="smtp-from"
            type="email"
            value={value.from}
            onChange={(e) => onChange({ ...value, from: e.target.value })}
            className="h-[34px] border border-border rounded-md px-3 text-[13.5px] bg-background focus:outline-0 focus:border-primary focus:ring-2 focus:ring-primary/20"
          />
        </div>
      </div>
    </div>
  );
}
