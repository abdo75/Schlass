import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ActorPicker } from "./ActorPicker";
import { AuditTimePicker } from "./AuditTimePicker";
import { PRESETS } from "./timePresets";
import { EventTypePicker } from "./EventTypePicker";
import { Pill } from "./Pill";
import { TargetPicker } from "./TargetPicker";
import { useOutsideClick } from "./useOutsideClick";
import { usePickerFetch } from "./usePickerFetch";
import type { AuditState, TargetsResponse } from "./types";
import { stateToParams } from "./useUrlState";

type Picker = "time" | "actor" | "target" | "event-type" | null;

const POPOVER_IDS: Record<Exclude<Picker, null>, { id: string; popup: "dialog" }> = {
  time: { id: "audit-time-popover", popup: "dialog" },
  actor: { id: "audit-actor-popover", popup: "dialog" },
  target: { id: "audit-target-popover", popup: "dialog" },
  "event-type": { id: "audit-event-type-popover", popup: "dialog" },
};

function isTargetsResponse(body: unknown): body is TargetsResponse {
  if (!body || typeof body !== "object") return false;
  return Array.isArray((body as { items?: unknown }).items);
}

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

  const hydrated = useRef(false);
  // Hydrate the target display label exactly once when the URL arrives with
  // both target_type and target_id but no remembered display string. The
  // `hydrated` ref guard runs inside the effect (refs cannot be read in
  // render). The fetch is gated by the URL state alone — usePickerFetch
  // dedupes by query, so a redundant skip=false on a re-mount is harmless.
  const needsLookup = Boolean(state.target_type && state.target_id && !targetDisplay);
  const hydrateParams = useMemo(() => {
    const p = stateToParams({ ...state, target_type: undefined, target_id: undefined, page: 1 });
    if (state.target_type) p.set("type", state.target_type);
    return p;
  }, [state]);
  const hydrate = usePickerFetch<TargetsResponse>("/api/audit/targets", hydrateParams, {
    skip: !needsLookup,
    validate: isTargetsResponse,
  });

  useEffect(() => {
    if (hydrated.current || !needsLookup || !hydrate.data) return;
    const match = hydrate.data.items.find(
      (it) => it.target_id === state.target_id && (it.target_type ?? state.target_type) === state.target_type,
    );
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (match) setTargetDisplay(match.display);
    hydrated.current = true;
  }, [needsLookup, hydrate.data, state.target_id, state.target_type]);

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
          <Pill
            variant="dashed"
            active={open === "time"}
            popoverId={POPOVER_IDS.time.id}
            popup={POPOVER_IDS.time.popup}
            onClick={() => setOpen(open === "time" ? null : "time")}
          >
            {state.until ? t("audit.timepicker.customRange") : presetLabel(state.since, t)}
          </Pill>
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
          state.actor ? (() => {
            const label = `${t("audit.panel.actor")}: ${state.actor === "system" ? t("audit.panel.system") : state.actor}`;
            return (
              <Pill
                variant="active"
                title={t("audit.refine.clearTitle")}
                ariaLabel={t("audit.refine.clearFilterAria", { label })}
                onClick={() => patch({ actor: undefined })}
              >
                {label}
              </Pill>
            );
          })() : (
            <Pill
              variant="dashed"
              active={open === "actor"}
              popoverId={POPOVER_IDS.actor.id}
              popup={POPOVER_IDS.actor.popup}
              onClick={() => setOpen(open === "actor" ? null : "actor")}
            >
              {t("audit.refine.actorOpener")}
            </Pill>
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
            <Pill
              variant="active"
              title={t("audit.refine.clearTitle")}
              ariaLabel={t("audit.refine.clearFilterAria", { label: state.target_type })}
              onClick={() => {
                patch({ target_type: undefined, target_id: undefined });
                setTargetDisplay(null);
                hydrated.current = false;
              }}
            >
              {state.target_id
                ? t("audit.refine.targetChipFull", {
                    type: t(`audit.panel.targetTypeLabel.${state.target_type}`, { defaultValue: state.target_type }),
                    display: targetDisplay ?? t("audit.refine.targetChipSelected"),
                  })
                : t("audit.refine.targetChipType", {
                    type: t(`audit.panel.targetTypeLabel.${state.target_type}`, { defaultValue: state.target_type }),
                  })}
            </Pill>
          ) : (
            <Pill
              variant="dashed"
              active={open === "target"}
              popoverId={POPOVER_IDS.target.id}
              popup={POPOVER_IDS.target.popup}
              onClick={() => setOpen(open === "target" ? null : "target")}
            >
              {t("audit.refine.targetOpener")}
            </Pill>
          )
        }
      >
        {open === "target" && (
          <TargetPicker
            state={state}
            onSelect={(target) => {
              patch({ target_type: target.target_type, target_id: target.target_id });
              setTargetDisplay(target.display ?? null);
              hydrated.current = true;
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
            <Pill
              variant="openerActive"
              active={open === "event-type"}
              popoverId={POPOVER_IDS["event-type"].id}
              popup={POPOVER_IDS["event-type"].popup}
              title={t("audit.refine.editSelectionTitle")}
              onClick={() => setOpen(open === "event-type" ? null : "event-type")}
            >
              {t("audit.refine.eventTypeCountChip", { count: state.event_types.length })}
            </Pill>
          ) : (
            <Pill
              variant="dashed"
              active={open === "event-type"}
              popoverId={POPOVER_IDS["event-type"].id}
              popup={POPOVER_IDS["event-type"].popup}
              onClick={() => setOpen(open === "event-type" ? null : "event-type")}
            >
              {t("audit.refine.eventTypeOpener")}
            </Pill>
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
        <Pill
          variant="active"
          title={t("audit.refine.clearTitle")}
          ariaLabel={t("audit.refine.clearFilterAria", { label: state.outcome })}
          onClick={() => patch({ outcome: undefined })}
        >
          {t("audit.refine.outcomeChip", { outcome: t(`audit.timeline.outcome.${state.outcome}`, { defaultValue: state.outcome }) })}
        </Pill>
      )}

      {hasRefinements && (
        <button
          type="button"
          className="ml-auto rounded-md px-2 py-1 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-foreground"
          onClick={() => {
            patch({ actor: undefined, target_type: undefined, target_id: undefined, event_types: undefined, outcome: undefined, q: undefined });
            setTargetDisplay(null);
            hydrated.current = false;
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

type Translator = (key: string, options?: Record<string, unknown>) => string;

function presetLabel(value: string, t: Translator): string {
  const match = PRESETS.find((preset) => preset.value === value);
  return t(match?.labelKey ?? "audit.timepicker.preset.last24h");
}
