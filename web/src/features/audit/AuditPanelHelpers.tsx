import type React from "react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";
import type { AuditItem, Outcome } from "./types";

export function OutcomeChip({
  outcome,
  variant = "panel",
  onFilter,
}: {
  outcome: Outcome;
  variant?: "panel" | "timeline";
  onFilter?: (outcome: Outcome) => void;
}) {
  const { t } = useTranslation();
  const label = t(`audit.timeline.outcome.${outcome}`, { defaultValue: outcome });
  const isTimeline = variant === "timeline";
  const ok = outcome === "success";
  const denied = outcome === "denied";
  const className = isTimeline
    ? cn(
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold",
        ok ? "bg-accent text-accent-foreground" : denied ? "bg-warning text-warning-foreground" : "bg-destructive/10 text-destructive",
        onFilter && "hover:ring-1 hover:ring-current",
      )
    : `outcome outcome--${outcome}${onFilter ? " outcome--button" : ""}`;
  const dot = isTimeline ? (
    <span className={cn("size-1.5 rounded-full", ok ? "bg-primary" : denied ? "bg-warning-border" : "bg-destructive")} />
  ) : (
    <span className="outcome-dot" aria-hidden="true" />
  );
  const content = (
    <>
      {dot}
      {label}
    </>
  );
  return onFilter ? (
    <button
      type="button"
      className={className}
      onClick={(event) => {
        event.stopPropagation();
        onFilter(outcome);
      }}
    >
      {content}
    </button>
  ) : (
    <span className={className}>{content}</span>
  );
}

export function SeverityBadge({ children }: { children: React.ReactNode }) {
  return <span className="severity-badge">{children}</span>;
}

export function Timestamp({ at, locale }: { at: string; locale: string }) {
  const d = new Date(at);
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const relative = relativeTime(d, locale);
  return (
    <div className="panel-when">
      <div className="panel-when-primary">
        <span className="d">{new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(d)}</span>
        <span className="t">{new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(d)}</span>
        <span className="tz">{tz}</span>
      </div>
      <div className="panel-when-secondary">{relative}</div>
    </div>
  );
}

export function ParticipantsSection({
  event,
  onActorFilter,
  onTargetFilter,
  onTargetTypeFilter,
}: {
  event: AuditItem;
  onActorFilter?: (actor: string) => void;
  onTargetFilter?: (target: { target_type: string; target_id: string }) => void;
  onTargetTypeFilter?: (targetType: string) => void;
}) {
  const { t } = useTranslation();
  const actor = event.actor_email ?? event.actor_display;
  const actorIsSystem = !event.actor_id && (!actor || actor.toLowerCase().startsWith("system"));
  const actorIsFormerUser = event.actor_pseudonymized || event.actor_display === "Former user";
  const targetLabel = targetLabelFor(event.target_type, t);
  const targetTypeLabel = humanizeTargetType(event.target_type, t);
  const targetDisplay = event.target_display ?? targetTypeLabel;
  return (
    <section className="panel-block panel-block--section">
      <h4 className="panel-heading">{t("audit.panel.participants")}</h4>
      <dl className="panel-facts">
        <dt>{t("audit.panel.actor")}</dt>
        <dd>
          {actorIsFormerUser ? (
            <span className="is-system" title={t("audit.panel.gdprTitle")}>{event.actor_display}</span>
          ) : actorIsSystem ? (
            onActorFilter ? (
              <a
                href={`?actor=system`}
                className="panel-fact-link"
                onClick={(click) => {
                  click.preventDefault();
                  onActorFilter("system");
                }}
              >
                {event.actor_display}
              </a>
            ) : (
              <span className="is-system">{event.actor_display}</span>
            )
          ) : onActorFilter ? (
            <a
              href={`?actor=${encodeURIComponent(actor)}`}
              className="panel-fact-link"
              onClick={(click) => {
                click.preventDefault();
                onActorFilter(actor);
              }}
            >
              {event.actor_display}
            </a>
          ) : event.actor_display}
        </dd>
        {targetDisplay && (
          <>
            <dt>{targetLabel}</dt>
            <dd>
              {onTargetFilter && event.target_type && event.target_id ? (
                <TargetLink
                  targetType={event.target_type}
                  targetId={event.target_id}
                  className="panel-fact-link"
                  onActivate={onTargetFilter}
                >
                  {targetDisplay}
                </TargetLink>
              ) : (
                <span className={!event.target_id ? "is-system" : undefined}>{targetDisplay}</span>
              )}
            </dd>
            {targetTypeLabel && (
              <>
                <dt>{t("audit.panel.targetType")}</dt>
                <dd>
                  {onTargetTypeFilter && event.target_type ? (
                    <TargetTypeLink
                      targetType={event.target_type}
                      className="panel-fact-link"
                      onActivate={onTargetTypeFilter}
                    >
                      {targetTypeLabel}
                    </TargetTypeLink>
                  ) : targetTypeLabel}
                </dd>
              </>
            )}
          </>
        )}
        {event.ip_address && (
          <>
            <dt>{t("audit.panel.fromIp")}</dt>
            <dd>{event.ip_address}</dd>
          </>
        )}
      </dl>
    </section>
  );
}

export function TechnicalDetails({
  event,
  onEventTypeFilter,
  onTargetFilter,
}: {
  event: AuditItem;
  onEventTypeFilter?: (eventType: string) => void;
  onTargetFilter?: (target: { target_type: string; target_id: string }) => void;
}) {
  const { t, i18n } = useTranslation();
  return (
    <section className="panel-block panel-block--tech">
      <h4 className="panel-heading">{t("audit.panel.technicalDetails")}</h4>
      <dl className="panel-tech-row"><dt>{t("audit.panel.eventId")}</dt><dd>{event.id}</dd></dl>
      <dl className="panel-tech-row"><dt>{t("audit.panel.eventType")}</dt><dd>
        {onEventTypeFilter ? (
          <a
            href={`?event_types=${encodeURIComponent(event.event_type)}`}
            className="panel-fact-link"
            onClick={(click) => {
              click.preventDefault();
              onEventTypeFilter(event.event_type);
            }}
          >
            {event.event_type}
          </a>
        ) : event.event_type}
      </dd></dl>
      <dl className="panel-tech-row"><dt>{t("audit.panel.actorId")}</dt><dd>{event.actor_id ?? "-"}</dd></dl>
      {event.target_id && <dl className="panel-tech-row"><dt>{t("audit.panel.targetId")}</dt><dd>
        {onTargetFilter && event.target_type ? (
          <TargetLink
            targetType={event.target_type}
            targetId={event.target_id}
            className="panel-fact-link"
            onActivate={onTargetFilter}
          >
            {event.target_id}
          </TargetLink>
        ) : event.target_id}
      </dd></dl>}
      <dl className="panel-tech-row"><dt>{t("audit.panel.recordedAt")}</dt><dd>{formatLocalDateTime(event.created_at, i18n.language)}</dd></dl>
    </section>
  );
}

function TargetLink({
  targetType,
  targetId,
  className,
  onActivate,
  children,
}: {
  targetType: string;
  targetId: string;
  className?: string;
  onActivate: (target: { target_type: string; target_id: string }) => void;
  children: React.ReactNode;
}) {
  return (
    <a
      href={`?target_type=${encodeURIComponent(targetType)}&target_id=${encodeURIComponent(targetId)}`}
      className={className}
      onClick={(click) => {
        click.preventDefault();
        onActivate({ target_type: targetType, target_id: targetId });
      }}
    >
      {children}
    </a>
  );
}

function TargetTypeLink({
  targetType,
  className,
  onActivate,
  children,
}: {
  targetType: string;
  className?: string;
  onActivate: (targetType: string) => void;
  children: React.ReactNode;
}) {
  return (
    <a
      href={`?target_type=${encodeURIComponent(targetType)}`}
      className={className}
      onClick={(click) => {
        click.preventDefault();
        onActivate(targetType);
      }}
    >
      {children}
    </a>
  );
}

function formatLocalDateTime(iso: string, locale: string): string {
  const d = new Date(iso);
  return new Intl.DateTimeFormat(locale, { dateStyle: "long", timeStyle: "long" }).format(d);
}

function relativeTime(date: Date, locale: string): string {
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const divisions: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["year", 60 * 60 * 24 * 365],
    ["month", 60 * 60 * 24 * 30],
    ["day", 60 * 60 * 24],
    ["hour", 60 * 60],
    ["minute", 60],
    ["second", 1],
  ];
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
  for (const [unit, amount] of divisions) {
    if (Math.abs(seconds) >= amount || unit === "second") {
      return formatter.format(Math.round(seconds / amount), unit);
    }
  }
  return formatter.format(0, "second");
}

type Translator = (key: string, options?: Record<string, unknown>) => string;

function targetLabelFor(targetType: string | null, t: Translator): string {
  switch (targetType) {
    case "client": return t("audit.panel.targetLabel.client");
    case "config": return t("audit.panel.targetLabel.config");
    case "user": return t("audit.panel.targetLabel.user");
    default: return t("audit.panel.targetLabel.default");
  }
}

function humanizeTargetType(targetType: string | null, t: Translator): string | null {
  if (!targetType) return null;
  const known = ["user", "client", "config", "instance_config", "signing_key", "instance", "audit_log", "permission", "session"];
  if (known.includes(targetType)) {
    return t(`audit.panel.targetTypeLabel.${targetType}`);
  }
  return targetType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
