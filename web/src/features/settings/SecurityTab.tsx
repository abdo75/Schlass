import type React from "react";
import { NumberInput } from "@/components/ui/NumberInput";
import type { SecuritySettings } from "./api";

interface Props {
  value: SecuritySettings;
  onChange: (next: SecuritySettings) => void;
  dirtyKeys: Set<keyof SecuritySettings>;
}

// Switch is an on/off boolean control, visually distinct from checkboxes.
// Matches V8 mockup: 36×20 pill with teal-on / neutral-off state and a
// sliding 16px thumb.
function Switch({
  checked,
  onChange,
  ariaLabel,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  ariaLabel: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      onClick={() => onChange(!checked)}
      className={
        "w-9 h-5 rounded-full relative cursor-pointer " +
        (checked ? "bg-primary" : "bg-muted-foreground/30")
      }
    >
      <span
        className={
          "absolute top-0.5 w-4 h-4 bg-background rounded-full shadow transition-all " +
          (checked ? "left-[18px]" : "left-0.5")
        }
      />
    </button>
  );
}

function DirtyDot({ show }: { show: boolean }) {
  if (!show) return null;
  return (
    <span
      className="inline-block w-1.5 h-1.5 rounded-full ml-2 align-middle"
      style={{ background: "oklch(0.76 0.15 80)" }}
      aria-hidden="true"
    />
  );
}

function Row({
  label,
  dirty,
  children,
}: {
  label: string;
  dirty: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[1fr_auto] items-center gap-5">
      <span className="text-[13.5px] font-medium text-foreground">
        {label}
        <DirtyDot show={dirty} />
      </span>
      {children}
    </div>
  );
}

function Card({
  title,
  desc,
  children,
}: {
  title: string;
  desc?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mb-4 rounded-xl border border-border bg-background overflow-hidden">
      <div className="px-6 pt-5 pb-1">
        <h3 className="text-[15px] font-semibold">{title}</h3>
        {desc && <p className="mt-1 text-[13px] text-muted-foreground leading-relaxed">{desc}</p>}
      </div>
      <div className="px-6 pt-[14px] pb-5 flex flex-col gap-[14px]">{children}</div>
    </div>
  );
}

export function SecurityTab({ value, onChange, dirtyKeys }: Props) {
  return (
    <div>
      <Card
        title="Multi-factor authentication"
        desc="Require every user to enrol a TOTP authenticator before receiving a session."
      >
        <Row label="Require for all users" dirty={dirtyKeys.has("mfa_required")}>
          <Switch
            checked={value.mfa_required}
            onChange={(v) => onChange({ ...value, mfa_required: v })}
            ariaLabel="Require for all users"
          />
        </Row>
      </Card>

      <Card title="Password policy">
        <Row label="Minimum length" dirty={dirtyKeys.has("password_min_length")}>
          <NumberInput
            value={value.password_min_length}
            min={8}
            max={128}
            ariaLabel="Minimum length"
            onChange={(n) => onChange({ ...value, password_min_length: n })}
          />
        </Row>
        <Row label="Require uppercase letter" dirty={dirtyKeys.has("password_require_upper")}>
          <Switch
            checked={value.password_require_upper}
            onChange={(v) => onChange({ ...value, password_require_upper: v })}
            ariaLabel="Require uppercase letter"
          />
        </Row>
        <Row label="Require digit" dirty={dirtyKeys.has("password_require_digit")}>
          <Switch
            checked={value.password_require_digit}
            onChange={(v) => onChange({ ...value, password_require_digit: v })}
            ariaLabel="Require digit"
          />
        </Row>
      </Card>

      <Card
        title="Account lockout"
        desc="Lock accounts after repeated failed sign-ins; locks auto-clear after the duration."
      >
        <Row label="Failed attempts before lock" dirty={dirtyKeys.has("lockout_threshold")}>
          <NumberInput
            value={value.lockout_threshold}
            min={1}
            max={50}
            ariaLabel="Failed attempts before lock"
            onChange={(n) => onChange({ ...value, lockout_threshold: n })}
          />
        </Row>
        <Row label="Unlock duration (minutes)" dirty={dirtyKeys.has("lockout_duration_secs")}>
          <NumberInput
            value={Math.round(value.lockout_duration_secs / 60)}
            min={1}
            max={1440}
            ariaLabel="Unlock duration (minutes)"
            onChange={(n) => onChange({ ...value, lockout_duration_secs: n * 60 })}
          />
        </Row>
      </Card>
    </div>
  );
}
