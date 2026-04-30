import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { renderSentence, severity } from "./catalog";
import type { AuditItem, ListResponse } from "./types";

export function AuditTimeline({ data, onSelect }: { data: ListResponse | null; onSelect: (event: AuditItem) => void }) {
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
            <TimelineRow key={item.id} item={item} onSelect={onSelect} />
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function TimelineRow({ item, onSelect }: { item: AuditItem; onSelect: (event: AuditItem) => void }) {
  const sentence = renderSentence(item.event_type, item.metadata, item.actor_display, item.target_display);
  const sev = severity(item.event_type, item.metadata);
  return (
    <TableRow
      data-testid="audit-event-row"
      className="cursor-pointer hover:bg-muted/35"
      onClick={() => onSelect(item)}
    >
      <TableCell className="px-4 py-3"><OutcomeChip outcome={item.outcome} /></TableCell>
      <TableCell className="px-4 py-3 text-xs text-muted-foreground">{formatRelative(item.created_at)}</TableCell>
      <TableCell className="min-w-[280px] whitespace-normal px-4 py-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-foreground">{sentence.text}</span>
          {item.actor_pseudonymized && <span className="rounded-md bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium text-amber-900">GDPR-erased</span>}
          {sev === "critical" && <span className="rounded-md bg-destructive/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.04em] text-destructive">Critical</span>}
        </div>
      </TableCell>
      <TableCell className="px-4 py-3 text-xs text-muted-foreground">{item.actor_id ? item.actor_display : "System"}</TableCell>
    </TableRow>
  );
}

function OutcomeChip({ outcome }: { outcome: AuditItem["outcome"] }) {
  const ok = outcome === "success";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold",
        ok ? "bg-accent text-accent-foreground" : "bg-destructive/10 text-destructive",
      )}
    >
      <span className={cn("size-1.5 rounded-full", ok ? "bg-primary" : "bg-destructive")} />
      {outcome}
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
