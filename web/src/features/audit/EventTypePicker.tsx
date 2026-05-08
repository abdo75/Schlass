import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { EVENT_TYPE_GROUPS } from "./eventTypeGroups";

export function EventTypePicker({ selected, onApply }: { selected: string[]; onApply: (eventTypes: string[]) => void }) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState<Set<string>>(() => new Set(selected));
  // Auto-expand only groups that already contain a selected event so the user
  // sees their current selection without an extra click. Other groups stay
  // collapsed for a cleaner overview when there are many categories.
  const initiallyExpanded = useMemo(
    () =>
      new Set(
        EVENT_TYPE_GROUPS.filter((group) =>
          group.events.some((event) => selected.includes(event.type)),
        ).map((group) => group.groupKey),
      ),
    [selected],
  );
  const [expanded, setExpanded] = useState<Set<string>>(initiallyExpanded);
  const count = draft.size;

  function toggle(type: string) {
    setDraft((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }

  function toggleGroup(groupKey: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(groupKey)) next.delete(groupKey);
      else next.add(groupKey);
      return next;
    });
  }

  return (
    <div
      id="audit-event-type-popover"
      role="dialog"
      aria-label={t("audit.refine.eventTypeOpener")}
      className="absolute left-0 top-9 z-30 flex max-h-[34rem] w-[28rem] flex-col rounded-lg border border-border bg-popover text-popover-foreground shadow-lg"
    >
      <div className="max-h-[29rem] overflow-y-auto p-2">
        {EVENT_TYPE_GROUPS.map((group) => {
          const isOpen = expanded.has(group.groupKey);
          const groupSelectedCount = group.events.filter((event) => draft.has(event.type)).length;
          return (
            <section key={group.groupKey} className="mb-1 last:mb-0">
              <button
                type="button"
                aria-expanded={isOpen}
                className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-xs font-semibold uppercase tracking-[0.06em] text-muted-foreground hover:bg-muted hover:text-foreground"
                onClick={() => toggleGroup(group.groupKey)}
              >
                <span className="flex items-center gap-1.5">
                  <span className={`inline-block transition-transform ${isOpen ? "rotate-90" : ""}`}>›</span>
                  {t(`audit.eventGroup.${group.groupKey}`)}
                </span>
                {groupSelectedCount > 0 && (
                  <span className="rounded-full bg-accent px-2 py-0.5 text-[10px] text-accent-foreground">
                    {groupSelectedCount}
                  </span>
                )}
              </button>
              {isOpen && (
                <div className="grid grid-cols-2 gap-1 px-2 pb-2 pt-1">
                  {group.events.map((event) => (
                    <label
                      key={event.type}
                      className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-muted"
                    >
                      <input type="checkbox" checked={draft.has(event.type)} onChange={() => toggle(event.type)} />
                      <span>{t(`audit.eventLabel.${event.labelKey}`)}</span>
                    </label>
                  ))}
                </div>
              )}
            </section>
          );
        })}
      </div>
      <div className="flex items-center gap-2 border-t border-border p-3">
        <span className="text-sm text-muted-foreground">{count} selected</span>
        <button
          type="button"
          className="ml-auto rounded-md px-2 py-1 text-sm text-muted-foreground hover:bg-muted"
          onClick={() => setDraft(new Set())}
        >
          Clear
        </button>
        <button
          type="button"
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-semibold text-primary-foreground"
          onClick={() => onApply([...draft])}
        >
          Apply
        </button>
      </div>
    </div>
  );
}
