import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ActorPicker } from "./ActorPicker";
import { AuditTimePicker } from "./AuditTimePicker";
import { EventTypePicker } from "./EventTypePicker";
import { TargetPicker } from "./TargetPicker";
import { useOutsideClick } from "./useOutsideClick";
import type { AuditState, TargetsResponse } from "./types";
import { stateToParams } from "./useUrlState";

type Picker = "time" | "actor" | "target" | "event-type" | null;

export function AuditFilterBar({
  state,
  onChange,
}: {
  state: AuditState;
  onChange: (patch: Partial<AuditState>) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<Picker>(null);
  const [targetDisplay, setTargetDisplay] = useState<string | null>(null);
  const hasRefinements = Boolean(state.actor || state.target_type || state.target_id || state.event_types?.length || state.outcome || state.q);

  // When URL state has a target_id but we don't know the display label yet (e.g.
  // page just loaded from a shareable URL), fetch it once.
  useEffect(() => {
    if (!state.target_type || !state.target_id || targetDisplay) return;
    const controller = new AbortController();
    const params = stateToParams({ ...state, target_type: undefined, target_id: undefined, page: 1 });
    params.set("type", state.target_type);
    fetch(`/api/audit/targets?${params}`, { signal: controller.signal })
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error("targets fetch failed"))))
      .then((body: TargetsResponse) => {
        const match = body.items.find((it) => it.target_id === state.target_id);
        if (match) setTargetDisplay(match.display);
      })
      .catch(() => undefined);
    return () => controller.abort();
  }, [state, targetDisplay]);

  function patch(next: Partial<AuditState>) {
    onChange({ ...next, page: 1 });
  }

  return (
    <div className="relative flex flex-wrap items-center gap-2 py-2 text-sm">
      <span className="mr-1 font-medium text-muted-foreground">{t("audit.refine.label")}</span>

      <PickerSlot
        active={open === "time"}
        onClose={() => setOpen(null)}
        chip={
          <Opener
            label={state.until ? "Custom range" : presetLabel(state.since)}
            active={open === "time"}
            onClick={() => setOpen(open === "time" ? null : "time")}
          />
        }
      >
        {open === "time" && (
          <AuditTimePicker
            state={state}
            onChange={(next) => {
              patch(next);
              setOpen(null);
            }}
          />
        )}
      </PickerSlot>

      <PickerSlot
        active={open === "actor"}
        onClose={() => setOpen(null)}
        chip={
          state.actor ? (
            <ActiveChip
              label={`${t("audit.panel.actor")}: ${state.actor === "system" ? t("audit.panel.system") : state.actor}`}
              onClear={() => patch({ actor: undefined })}
            />
          ) : (
            <Opener
              label={t("audit.refine.actorOpener")}
              active={open === "actor"}
              onClick={() => setOpen(open === "actor" ? null : "actor")}
            />
          )
        }
      >
        {open === "actor" && (
          <ActorPicker
            state={state}
            onSelect={(actor) => {
              patch({ actor });
              setOpen(null);
            }}
          />
        )}
      </PickerSlot>

      <PickerSlot
        active={open === "target"}
        onClose={() => setOpen(null)}
        chip={
          state.target_type ? (
            <ActiveChip
              label={`${t("audit.panel.target")}: ${state.target_type}${state.target_id ? ` — ${targetDisplay ?? "selected"}` : ""}`}
              onClear={() => {
                patch({ target_type: undefined, target_id: undefined });
                setTargetDisplay(null);
              }}
            />
          ) : (
            <Opener
              label={t("audit.refine.targetOpener")}
              active={open === "target"}
              onClick={() => setOpen(open === "target" ? null : "target")}
            />
          )
        }
      >
        {open === "target" && (
          <TargetPicker
            state={state}
            onSelect={(target) => {
              patch({ target_type: target.target_type, target_id: target.target_id });
              setTargetDisplay(target.display ?? null);
              setOpen(null);
            }}
          />
        )}
      </PickerSlot>

      <PickerSlot
        active={open === "event-type"}
        onClose={() => setOpen(null)}
        chip={
          state.event_types?.length ? (
            // Multi-select: click re-opens picker; clearing happens via the
            // picker's Clear button (single-value chips below clear on click).
            <ActiveOpener
              label={`Event type: ${state.event_types.length} selected`}
              active={open === "event-type"}
              onClick={() => setOpen(open === "event-type" ? null : "event-type")}
            />
          ) : (
            <Opener
              label={t("audit.refine.eventTypeOpener")}
              active={open === "event-type"}
              onClick={() => setOpen(open === "event-type" ? null : "event-type")}
            />
          )
        }
      >
        {open === "event-type" && (
          <EventTypePicker
            selected={state.event_types ?? []}
            onApply={(eventTypes) => {
              patch({ event_types: eventTypes.length ? eventTypes : undefined });
              setOpen(null);
            }}
          />
        )}
      </PickerSlot>

      {state.outcome && (
        <ActiveChip
          label={`Outcome: ${state.outcome}`}
          onClear={() => patch({ outcome: undefined })}
        />
      )}

      {hasRefinements && (
        <button
          type="button"
          className="ml-auto rounded-md px-2 py-1 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
          onClick={() => {
            patch({ actor: undefined, target_type: undefined, target_id: undefined, event_types: undefined, outcome: undefined, q: undefined });
            setTargetDisplay(null);
          }}
        >
          {t("audit.refine.clear")}
        </button>
      )}
    </div>
  );
}

function PickerSlot({
  active,
  onClose,
  chip,
  children,
}: {
  active: boolean;
  onClose: () => void;
  chip: React.ReactNode;
  children?: React.ReactNode;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  useOutsideClick(ref, active, onClose);
  return (
    <span ref={ref} className="relative">
      {chip}
      {children}
    </span>
  );
}

function Opener({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-expanded={active}
      className="rounded-full border border-dashed border-border bg-background px-3 py-1.5 text-xs font-medium text-muted-foreground hover:border-primary/40 hover:text-foreground"
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function ActiveChip({ label, onClear }: { label: string; onClear: () => void }) {
  return (
    <button
      type="button"
      title="Click to clear"
      aria-label={`Clear filter: ${label}`}
      className="inline-flex items-center gap-1 rounded-full border border-primary/30 bg-accent px-3 py-1.5 text-xs font-medium text-accent-foreground transition-colors hover:bg-accent/70"
      onClick={onClear}
    >
      {label}
    </button>
  );
}

function ActiveOpener({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-expanded={active}
      title="Click to edit selection"
      className="inline-flex items-center gap-1 rounded-full border border-primary/30 bg-accent px-3 py-1.5 text-xs font-medium text-accent-foreground transition-colors hover:bg-accent/70"
      onClick={onClick}
    >
      {label}
    </button>
  );
}

function presetLabel(value: string) {
  switch (value) {
    case "1h":
      return "Last hour";
    case "7d":
      return "Last 7 days";
    case "30d":
      return "Last 30 days";
    case "24h":
    default:
      return "Last 24 hours";
  }
}
