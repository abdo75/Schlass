import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { useOutsideClick } from "./useOutsideClick";

export type AuditRange = { from: Date; to: Date };
type Slot = "from" | "to";
type ViewMode = "day" | "month" | "year";
type TimeGrid = { slot: Slot; part: "hour" | "minute" } | null;

function dayKey(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function buildLocaleNames(locale: string) {
  const monthShort = new Intl.DateTimeFormat(locale, { month: "short" });
  const monthLong = new Intl.DateTimeFormat(locale, { month: "long" });
  const weekday = new Intl.DateTimeFormat(locale, { weekday: "narrow" });
  const months: string[] = [];
  const monthsLong: string[] = [];
  for (let i = 0; i < 12; i++) {
    const ref = new Date(2024, i, 1);
    months.push(monthShort.format(ref));
    monthsLong.push(monthLong.format(ref));
  }
  // Mon=2024-01-01 … Sun=2024-01-07
  const weekdays = Array.from({ length: 7 }, (_, i) => weekday.format(new Date(2024, 0, i + 1)));
  return { months, monthsLong, weekdays };
}

export function AuditCalendar({ value, onChange }: { value: AuditRange; onChange: (range: AuditRange) => void }) {
  const { t, i18n } = useTranslation();
  const [activeSlot, setActiveSlot] = useState<Slot>("from");
  const [view, setView] = useState<ViewMode>("day");
  const [cursor, setCursor] = useState(() => new Date(value.from));
  const [timeGrid, setTimeGrid] = useState<TimeGrid>(null);
  const days = useMemo(() => buildDays(cursor), [cursor]);
  const { months: MONTHS, monthsLong: MONTH_NAMES, weekdays: WEEKDAYS } = useMemo(
    () => buildLocaleNames(i18n.language),
    [i18n.language],
  );
  const dayRefs = useRef(new Map<string, HTMLButtonElement>());
  const pendingFocusRef = useRef<string | null>(null);
  const currentYear = new Date().getFullYear();
  const yearStart = Math.floor(cursor.getFullYear() / 12) * 12;

  useEffect(() => {
    const target = pendingFocusRef.current;
    if (!target) return;
    dayRefs.current.get(target)?.focus();
    pendingFocusRef.current = null;
  }, [days]);

  function focusDay(date: Date) {
    const key = dayKey(date);
    const ref = dayRefs.current.get(key);
    if (ref) {
      ref.focus();
    } else {
      pendingFocusRef.current = key;
    }
  }

  function moveFocus(currentDay: Date, deltaDays: number) {
    const next = new Date(currentDay);
    next.setDate(currentDay.getDate() + deltaDays);
    const crossedMonth = next.getFullYear() !== cursor.getFullYear() || next.getMonth() !== cursor.getMonth();
    if (crossedMonth) {
      pendingFocusRef.current = dayKey(next);
      setCursor(new Date(next.getFullYear(), next.getMonth(), 1));
    } else {
      focusDay(next);
    }
  }

  function moveFocusByMonth(currentDay: Date, deltaMonths: number) {
    const next = new Date(currentDay);
    next.setMonth(currentDay.getMonth() + deltaMonths);
    pendingFocusRef.current = dayKey(next);
    setCursor(new Date(next.getFullYear(), next.getMonth(), 1));
  }

  function moveFocusToWeekEdge(currentDay: Date, edge: "start" | "end") {
    const dayOfWeek = (currentDay.getDay() + 6) % 7;
    const offset = edge === "start" ? -dayOfWeek : 6 - dayOfWeek;
    moveFocus(currentDay, offset);
  }

  function onGridKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    const target = event.target as HTMLElement;
    const iso = target.dataset.day;
    if (!iso) return;
    const [y, m, d] = iso.split("-").map(Number);
    const current = new Date(y, m - 1, d);
    switch (event.key) {
      case "ArrowLeft": event.preventDefault(); moveFocus(current, -1); break;
      case "ArrowRight": event.preventDefault(); moveFocus(current, 1); break;
      case "ArrowUp": event.preventDefault(); moveFocus(current, -7); break;
      case "ArrowDown": event.preventDefault(); moveFocus(current, 7); break;
      case "PageUp": event.preventDefault(); moveFocusByMonth(current, -1); break;
      case "PageDown": event.preventDefault(); moveFocusByMonth(current, 1); break;
      case "Home": event.preventDefault(); moveFocusToWeekEdge(current, "start"); break;
      case "End": event.preventDefault(); moveFocusToWeekEdge(current, "end"); break;
    }
  }

  function updateSlot(slot: Slot, next: Date) {
    const draft: AuditRange = { ...value, [slot]: next };
    if (draft.from > draft.to) {
      onChange({ from: draft.to, to: draft.from });
    } else {
      onChange(draft);
    }
  }

  function selectDay(day: Date) {
    const current = value[activeSlot];
    const next = new Date(day);
    next.setHours(current.getHours(), current.getMinutes(), 0, 0);
    updateSlot(activeSlot, next);
    setCursor(day);
  }

  function setPart(slot: Slot, part: "hour" | "minute", raw: string | number) {
    const parsed = typeof raw === "number" ? raw : Number.parseInt(raw || "0", 10);
    const n = Number.isNaN(parsed) ? 0 : parsed;
    const next = new Date(value[slot]);
    if (part === "hour") next.setHours(clamp(n, 0, 23));
    else next.setMinutes(clamp(n, 0, 59));
    next.setSeconds(0, 0);
    updateSlot(slot, next);
  }

  return (
    <div className="w-[280px] rounded-lg bg-popover p-3 text-popover-foreground">
      <div className="mb-2 flex items-center justify-between gap-1">
        <button type="button" aria-label={t("audit.calendar.previousMonth")} className="cal-nav inline-flex size-7 items-center justify-center rounded-md border border-border bg-background hover:bg-muted" onClick={() => setCursor(shiftCursor(cursor, view, -1))}><ChevronLeftIcon className="size-4" /></button>
        <div className="flex justify-center gap-1">
          <button type="button" className="cal-select h-7 rounded-md px-2 text-sm font-semibold hover:bg-muted" onClick={() => setView("month")}>{MONTH_NAMES[cursor.getMonth()]}</button>
          <button type="button" className="cal-select h-7 rounded-md px-2 text-sm font-semibold hover:bg-muted" onClick={() => setView("year")}>{cursor.getFullYear()}</button>
        </div>
        <button type="button" aria-label={t("audit.calendar.nextMonth")} className="cal-nav inline-flex size-7 items-center justify-center rounded-md border border-border bg-background hover:bg-muted" onClick={() => setCursor(shiftCursor(cursor, view, 1))}><ChevronRightIcon className="size-4" /></button>
      </div>

      {view === "day" && (
        <div
          role="grid"
          className="grid grid-cols-7 gap-0.5 font-mono text-sm focus-within:outline-none"
          onKeyDown={onGridKeyDown}
        >
          {WEEKDAYS.map((d, i) => <div key={`wd-${i}`} role="columnheader" className="py-1 text-center text-[11px] uppercase text-muted-foreground">{d}</div>)}
          {days.map((day) => {
            const key = dayKey(day);
            return (
              <button
                key={day.toISOString()}
                ref={(node) => {
                  if (node) dayRefs.current.set(key, node);
                  else dayRefs.current.delete(key);
                }}
                data-day={key}
                type="button"
                className={cn(
                  "cal-cell flex h-8 items-center justify-center rounded-md text-sm hover:bg-muted focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring",
                  day.getMonth() !== cursor.getMonth() && "outside text-muted-foreground/50",
                  sameDay(day, new Date()) && "is-today bg-muted font-semibold",
                  sameDay(day, value.from) && "is-range-start bg-primary text-primary-foreground hover:bg-primary",
                  sameDay(day, value.to) && "is-range-end bg-primary text-primary-foreground hover:bg-primary",
                  day > value.from && day < value.to && "is-in-range bg-accent text-accent-foreground hover:bg-accent",
                )}
                onClick={() => selectDay(day)}
              >
                {day.getDate()}
              </button>
            );
          })}
        </div>
      )}

      {view === "month" && (
        <div className="grid grid-cols-3 gap-1">
          {MONTHS.map((month, index) => (
            <button key={month} type="button" className="rounded-md px-2 py-2 text-sm hover:bg-muted" onClick={() => { setCursor(new Date(cursor.getFullYear(), index, 1)); setView("day"); }}>{month}</button>
          ))}
        </div>
      )}

      {view === "year" && (
        <div className="grid grid-cols-3 gap-1">
          {Array.from({ length: 12 }, (_, i) => yearStart + i).map((year) => (
            <button
              key={year}
              type="button"
              disabled={year > currentYear}
              className={cn("rounded-md px-2 py-2 text-sm hover:bg-muted disabled:pointer-events-none disabled:opacity-40", year > currentYear && "is-disabled")}
              onClick={() => { setCursor(new Date(year, cursor.getMonth(), 1)); setView("day"); }}
            >
              {year}
            </button>
          ))}
        </div>
      )}

      <div className="mt-3 grid gap-2 border-t border-border pt-3">
        <TimeRow slot="from" active={activeSlot === "from"} value={value.from} onActivate={() => setActiveSlot("from")} onPart={setPart} timeGrid={timeGrid} setTimeGrid={setTimeGrid} />
        <TimeRow slot="to" active={activeSlot === "to"} value={value.to} onActivate={() => setActiveSlot("to")} onPart={setPart} timeGrid={timeGrid} setTimeGrid={setTimeGrid} />
      </div>
    </div>
  );
}

function TimeRow({
  slot,
  active,
  value,
  onActivate,
  onPart,
  timeGrid,
  setTimeGrid,
}: {
  slot: Slot;
  active: boolean;
  value: Date;
  onActivate: () => void;
  onPart: (slot: Slot, part: "hour" | "minute", value: string | number) => void;
  timeGrid: TimeGrid;
  setTimeGrid: (grid: TimeGrid) => void;
}) {
  const { t } = useTranslation();
  return (
    <div data-testid={`time-row-${slot}`} className="grid grid-cols-[56px_1fr] items-center gap-3">
      <button type="button" className={cn("text-left text-xs font-semibold uppercase tracking-[0.06em] text-muted-foreground", active && "text-primary")} onClick={onActivate}>{t(`audit.calendar.slot.${slot}`)}</button>
      <TimeGridContainer
        slot={slot}
        value={value}
        onPart={onPart}
        timeGrid={timeGrid}
        setTimeGrid={setTimeGrid}
      />
    </div>
  );
}

function TimeGridContainer({
  slot,
  value,
  onPart,
  timeGrid,
  setTimeGrid,
}: {
  slot: Slot;
  value: Date;
  onPart: (slot: Slot, part: "hour" | "minute", value: string | number) => void;
  timeGrid: TimeGrid;
  setTimeGrid: (grid: TimeGrid) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const open = timeGrid?.slot === slot;
  useOutsideClick(ref, open, () => setTimeGrid(null));
  return (
    <div ref={ref} className="relative inline-flex items-center gap-1">
      <TimePart slot={slot} part="hour" value={value.getHours()} onPart={onPart} setTimeGrid={setTimeGrid} />
      <span className="text-muted-foreground">:</span>
      <TimePart slot={slot} part="minute" value={value.getMinutes()} onPart={onPart} setTimeGrid={setTimeGrid} />
      {open && (
        <div className="absolute left-0 top-8 z-40 grid w-52 grid-cols-6 gap-1 rounded-lg border border-border bg-popover p-2 shadow-lg">
          {(timeGrid.part === "hour"
            ? Array.from({ length: 24 }, (_, i) => i)
            : Array.from({ length: 12 }, (_, i) => i * 5)
          ).map((n) => (
            <button
              key={n}
              type="button"
              className="rounded-md px-2 py-1 text-sm hover:bg-muted"
              onClick={() => {
                onPart(slot, timeGrid.part, n);
                setTimeGrid(null);
              }}
            >
              {pad(n)}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function TimePart({ slot, part, value, onPart, setTimeGrid }: { slot: Slot; part: "hour" | "minute"; value: number; onPart: (slot: Slot, part: "hour" | "minute", value: string | number) => void; setTimeGrid: (grid: TimeGrid) => void }) {
  const { t } = useTranslation();
  const slotLabel = t(`audit.calendar.slot.${slot}`);
  const partLabel = t(`audit.calendar.part.${part}`);
  return (
    <span className="inline-flex h-8 overflow-hidden rounded-md border border-border bg-background focus-within:border-primary/50">
      <input
        aria-label={t("audit.calendar.timeAria", { slot: slotLabel, part: partLabel })}
        value={pad(value)}
        maxLength={2}
        inputMode="numeric"
        className="w-9 bg-transparent text-center text-sm outline-none"
        onChange={(event) => onPart(slot, part, event.target.value)}
        onBlur={(event) => onPart(slot, part, event.target.value)}
      />
      <button type="button" aria-label={t("audit.calendar.pickTimeAria", { slot: slotLabel, part: partLabel })} className="w-6 border-l border-border text-xs text-muted-foreground hover:bg-muted" onClick={() => setTimeGrid({ slot, part })}>▾</button>
    </span>
  );
}

function buildDays(cursor: Date): Date[] {
  const first = new Date(cursor.getFullYear(), cursor.getMonth(), 1);
  const mondayOffset = (first.getDay() + 6) % 7;
  const start = new Date(first);
  start.setDate(first.getDate() - mondayOffset);
  return Array.from({ length: 42 }, (_, i) => {
    const d = new Date(start);
    d.setDate(start.getDate() + i);
    return d;
  });
}

function shiftCursor(cursor: Date, view: ViewMode, amount: number): Date {
  const next = new Date(cursor);
  if (view === "year") next.setFullYear(cursor.getFullYear() + amount * 12);
  else next.setMonth(cursor.getMonth() + amount);
  return next;
}

function sameDay(a: Date, b: Date) {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

function clamp(n: number, min: number, max: number) {
  return Math.min(max, Math.max(min, n));
}

function pad(n: number) {
  return String(n).padStart(2, "0");
}
