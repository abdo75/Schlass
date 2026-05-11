import { useState } from "react";
import { useTranslation } from "react-i18next";
import { AuditCalendar, type AuditRange } from "./AuditCalendar";
import { PRESETS } from "./timePresets";
import type { AuditState } from "./types";

/**
 * Popover content for the time-range picker. Anchor (chip + open/close
 * toggle) lives in AuditFilterBar via PickerSlot.
 */
export function AuditTimePicker({
  state,
  onChange,
}: {
  state: AuditState;
  onChange: (patch: Partial<AuditState>) => void;
}) {
  const { t } = useTranslation();
  const [mode, setMode] = useState<"preset" | "custom">(state.until ? "custom" : "preset");
  const [preset, setPreset] = useState(state.until ? "24h" : state.since);
  const [range, setRange] = useState<AuditRange>(() => stateToRange(state));

  function apply() {
    if (mode === "custom") {
      onChange({ since: range.from.toISOString(), until: range.to.toISOString() });
    } else {
      onChange({ since: preset, until: undefined });
    }
  }

  return (
    <div
      id="audit-time-popover"
      role="dialog"
      aria-label={t("audit.timepicker.ariaLabel")}
      className="absolute left-0 top-9 z-30 flex items-start gap-2 text-popover-foreground"
    >
      <div className="w-60 rounded-lg border border-border bg-popover p-3 shadow-lg">
        <div className="grid gap-1">
          {PRESETS.map((item) => (
            <button
              key={item.value}
              type="button"
              className={`rounded-md px-2.5 py-1.5 text-left text-sm font-medium ${
                mode === "preset" && preset === item.value
                  ? "bg-accent text-accent-foreground"
                  : "hover:bg-muted"
              }`}
              onClick={() => {
                setMode("preset");
                setPreset(item.value);
              }}
            >
              {t(item.labelKey)}
            </button>
          ))}
          <button
            type="button"
            className={`rounded-md px-2.5 py-1.5 text-left text-sm font-medium ${
              mode === "custom" ? "bg-accent text-accent-foreground" : "hover:bg-muted"
            }`}
            onClick={() => setMode("custom")}
          >
            {t("audit.timepicker.customRange")}
          </button>
        </div>
        <div className="mt-3 flex justify-end border-t border-border pt-3">
          <button
            type="button"
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground"
            onClick={apply}
          >
            {t("audit.timepicker.apply")}
          </button>
        </div>
      </div>
      {mode === "custom" && (
        <div className="rounded-lg border border-border bg-popover p-2 shadow-lg">
          <AuditCalendar value={range} onChange={setRange} />
        </div>
      )}
    </div>
  );
}

function stateToRange(state: AuditState): AuditRange {
  const to = state.until ? new Date(state.until) : new Date();
  const from = state.since && state.since.includes("T") ? new Date(state.since) : relativeFrom(state.since, to);
  return { from, to };
}

function relativeFrom(value: string, to: Date): Date {
  const n = Number.parseInt(value.slice(0, -1), 10);
  const amount = Number.isNaN(n) ? 24 : n;
  const from = new Date(to);
  if (value.endsWith("d")) from.setDate(to.getDate() - amount);
  else from.setHours(to.getHours() - amount);
  return from;
}
