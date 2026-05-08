import type React from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
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
  const items = data?.items ?? [];

  if (items.length === 0) {
    return <div className="rounded-lg border border-border bg-background p-6 text-sm text-muted-foreground">No audit events found.</div>;
  }

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-background">
      <Table>
        <TableHeader className="bg-muted/35">
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-[110px] px-4 py-3 text-[11px] uppercase tracking-[0.05em] text-muted-foreground">Outcome</TableHead>
            <TableHead className="w-[140px] px-4 py-3 text-[11px] uppercase tracking-[0.05em] text-muted-foreground">When</TableHead>
            <TableHead className="px-4 py-3 text-[11px] uppercase tracking-[0.05em] text-muted-foreground">Activity</TableHead>
            <TableHead className="w-[190px] px-4 py-3 text-[11px] uppercase tracking-[0.05em] text-muted-foreground">Actor</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((item) => (
            <TimelineRow
              key={item.id}
              item={item}
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
  onSelect,
  onActorFilter,
  onEventTypeFilter,
  onOutcomeFilter,
}: {
  item: AuditItem;
  onSelect: (event: AuditItem) => void;
  onActorFilter?: (actor: string) => void;
  onEventTypeFilter?: (eventType: string) => void;
  onOutcomeFilter?: (outcome: Outcome) => void;
}) {
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
        <OutcomeChip
          outcome={item.outcome}
          onClick={onOutcomeFilter ? (event) => {
            event.stopPropagation();
            onOutcomeFilter(item.outcome);
          } : undefined}
        />
      </TableCell>
      <TableCell className="px-4 py-3 text-xs text-muted-foreground">{formatRelative(item.created_at)}</TableCell>
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
          {item.actor_pseudonymized && <span className="rounded-md border border-warning-border bg-warning px-1.5 py-0.5 text-[10px] font-medium text-warning-foreground">GDPR-erased</span>}
          {sev === "critical" && <span className="rounded-md bg-destructive/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.04em] text-destructive">Critical</span>}
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
            {item.actor_id ? item.actor_display : "System"}
          </button>
        ) : (
          item.actor_id ? item.actor_display : "System"
        )}
      </TableCell>
    </TableRow>
  );
}

function OutcomeChip({ outcome, onClick }: { outcome: AuditItem["outcome"]; onClick?: React.MouseEventHandler<HTMLButtonElement> }) {
  const ok = outcome === "success";
  const denied = outcome === "denied";
  const className = cn(
    "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold",
    ok ? "bg-accent text-accent-foreground" : denied ? "bg-warning text-warning-foreground" : "bg-destructive/10 text-destructive",
    onClick && "hover:ring-1 hover:ring-current",
  );
  const content = (
    <>
      <span className={cn("size-1.5 rounded-full", ok ? "bg-primary" : denied ? "bg-warning-border" : "bg-destructive")} />
      {outcome}
    </>
  );
  return onClick ? (
    <button type="button" className={className} onClick={onClick}>{content}</button>
  ) : (
    <span
      className={className}
    >
      {content}
    </span>
  );
}

function formatRelative(value: string): string {
  const then = new Date(value).getTime();
  const delta = Math.max(0, Date.now() - then);
  const minutes = Math.floor(delta / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.floor(hours / 24);
  return `${days} d ago`;
}
