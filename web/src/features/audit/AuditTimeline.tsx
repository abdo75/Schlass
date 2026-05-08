import { useTranslation } from "react-i18next";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { OutcomeChip } from "./AuditPanelHelpers";
import { renderSentence, severity } from "./catalog";
import type { AuditItem, ListResponse, Outcome } from "./types";

export function AuditTimeline({
  data,
  onSelect,
  onActorFilter,
  onEventTypeFilter,
  onOutcomeFilter,
}: {
  data: ListResponse | null;
  onSelect: (event: AuditItem) => void;
  onActorFilter?: (actor: string) => void;
  onEventTypeFilter?: (eventType: string) => void;
  onOutcomeFilter?: (outcome: Outcome) => void;
}) {
  const { t, i18n } = useTranslation();
  const items = data?.items ?? [];

  if (items.length === 0) {
    return <div className="rounded-lg border border-border bg-background p-6 text-sm text-muted-foreground">{t("audit.timeline.empty")}</div>;
  }

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background">
      <Table>
        <TableHeader className="bg-muted/35">
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-[110px] px-4 py-3 text-[11px] uppercase tracking-[0.05em] text-muted-foreground">{t("audit.timeline.columns.outcome")}</TableHead>
            <TableHead className="w-[140px] px-4 py-3 text-[11px] uppercase tracking-[0.05em] text-muted-foreground">{t("audit.timeline.columns.when")}</TableHead>
            <TableHead className="px-4 py-3 text-[11px] uppercase tracking-[0.05em] text-muted-foreground">{t("audit.timeline.columns.activity")}</TableHead>
            <TableHead className="w-[190px] px-4 py-3 text-[11px] uppercase tracking-[0.05em] text-muted-foreground">{t("audit.timeline.columns.actor")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((item) => (
            <TimelineRow
              key={item.id}
              item={item}
              locale={i18n.language}
              onSelect={onSelect}
              onActorFilter={onActorFilter}
              onEventTypeFilter={onEventTypeFilter}
              onOutcomeFilter={onOutcomeFilter}
            />
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function TimelineRow({
  item,
  locale,
  onSelect,
  onActorFilter,
  onEventTypeFilter,
  onOutcomeFilter,
}: {
  item: AuditItem;
  locale: string;
  onSelect: (event: AuditItem) => void;
  onActorFilter?: (actor: string) => void;
  onEventTypeFilter?: (eventType: string) => void;
  onOutcomeFilter?: (outcome: Outcome) => void;
}) {
  const { t } = useTranslation();
  const sentence = renderSentence(item.event_type, item.metadata, item.actor_display, item.target_display);
  const sev = severity(item.event_type, item.metadata);
  // Filter on email when present, "system" for null actor. A signed-in actor
  // whose email has been deleted/pseudonymized cannot be filtered uniquely —
  // the cell renders as a static span (matches the pseudonymized branch
  // below).
  const actorFilterValue = item.actor_id ? item.actor_email : "system";
  const actorIsUnfilterable = item.actor_pseudonymized || (item.actor_id !== null && !item.actor_email);
  return (
    <TableRow
      data-testid="audit-event-row"
      className="cursor-pointer hover:bg-muted/35 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-ring"
      tabIndex={0}
      role="button"
      aria-label={sentence.text}
      onClick={() => onSelect(item)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect(item);
        }
      }}
    >
      <TableCell className="px-4 py-3">
        <OutcomeChip outcome={item.outcome} variant="timeline" onFilter={onOutcomeFilter} />
      </TableCell>
      <TableCell className="px-4 py-3 text-xs text-muted-foreground">{formatRelative(item.created_at, locale)}</TableCell>
      <TableCell className="min-w-[280px] whitespace-normal px-4 py-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-foreground">{sentence.text}</span>
          {onEventTypeFilter ? (
            <button
              type="button"
              className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground underline decoration-dotted underline-offset-2 hover:text-foreground"
              onClick={(event) => {
                event.stopPropagation();
                onEventTypeFilter(item.event_type);
              }}
            >
              {item.event_type}
            </button>
          ) : (
            <span className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{item.event_type}</span>
          )}
          {item.actor_pseudonymized && <span className="rounded-md border border-warning-border bg-warning px-1.5 py-0.5 text-[10px] font-medium text-warning-foreground">{t("audit.timeline.gdprErased")}</span>}
          {sev === "critical" && <span className="rounded-md bg-destructive/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.04em] text-destructive">{t("audit.severity.critical")}</span>}
        </div>
      </TableCell>
      <TableCell className="px-4 py-3 text-xs text-muted-foreground">
        {actorIsUnfilterable ? (
          <span>{item.actor_display}</span>
        ) : onActorFilter && actorFilterValue ? (
          <button
            type="button"
            className="text-left underline decoration-dotted underline-offset-2 hover:text-foreground"
            onClick={(event) => {
              event.stopPropagation();
              onActorFilter(actorFilterValue);
            }}
          >
            {item.actor_id ? item.actor_display : t("audit.panel.system")}
          </button>
        ) : (
          item.actor_id ? item.actor_display : t("audit.panel.system")
        )}
      </TableCell>
    </TableRow>
  );
}

function formatRelative(value: string, locale: string): string {
  const then = new Date(value).getTime();
  const seconds = Math.round((then - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  const divisions: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["day", 60 * 60 * 24],
    ["hour", 60 * 60],
    ["minute", 60],
    ["second", 1],
  ];
  for (const [unit, amount] of divisions) {
    if (Math.abs(seconds) >= amount || unit === "second") {
      return formatter.format(Math.round(seconds / amount), unit);
    }
  }
  return formatter.format(0, "second");
}
