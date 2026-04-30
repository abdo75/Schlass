import type React from "react";
import { useTranslation } from "react-i18next";
import type { AuditItem, Outcome } from "./types";

export function OutcomeChip({ outcome }: { outcome: Outcome }) {
  return (
    <span className={`outcome outcome--${outcome}`}>
      <span className="outcome-dot" aria-hidden="true" />
      {outcome}
    </span>
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
}: {
  event: AuditItem;
  onActorFilter?: (actor: string) => void;
  onTargetFilter?: (target: { target_type: string; target_id: string }) => void;
}) {
  const { t } = useTranslation();
  const actor = event.actor_email ?? event.actor_display;
  const actorIsSystem = !event.actor_id && (!actor || actor.toLowerCase().startsWith("system"));
  const actorIsFormerUser = event.actor_pseudonymized || event.actor_display === "Former user";
  const targetLabel = targetLabelFor(event.target_type);
  const targetTypeLabel = humanizeTargetType(event.target_type);
  return (
    <section className="panel-block panel-block--section">
      <h4 className="panel-heading">{t("audit.panel.participants")}</h4>
      <dl className="panel-facts">
        <dt>{t("audit.panel.actor")}</dt>
        <dd>
          {actorIsFormerUser ? (
            <span className="is-system" title="GDPR Art. 17 erasure">{event.actor_display}</span>
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
        {event.target_display && (
          <>
            <dt>{targetLabel}</dt>
            <dd>
              {onTargetFilter && event.target_type ? (
                <a
                  href={`?target_type=${encodeURIComponent(event.target_type)}${event.target_id ? `&target_id=${encodeURIComponent(event.target_id)}` : ""}`}
                  className="panel-fact-link"
                  onClick={(click) => {
                    click.preventDefault();
                    onTargetFilter({ target_type: event.target_type!, target_id: event.target_id ?? "" });
                  }}
                >
                  {event.target_display}
                </a>
              ) : event.target_display}
            </dd>
            {targetTypeLabel && (
              <>
                <dt>{t("audit.panel.targetType")}</dt>
                <dd>{targetTypeLabel}</dd>
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

export function TechnicalDetails({ event, onEventTypeFilter }: { event: AuditItem; onEventTypeFilter?: (eventType: string) => void }) {
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
      {event.target_id && <dl className="panel-tech-row"><dt>{t("audit.panel.targetId")}</dt><dd>{event.target_id}</dd></dl>}
      <dl className="panel-tech-row"><dt>{t("audit.panel.recordedAt")}</dt><dd>{formatLocalDateTime(event.created_at, i18n.language)}</dd></dl>
    </section>
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

function targetLabelFor(targetType: string | null): string {
  switch (targetType) {
    case "client": return "Client";
    case "config": return "Setting";
    case "user": return "Target user";
    default: return "Target";
  }
}

function humanizeTargetType(targetType: string | null): string | null {
  if (!targetType) return null;
  switch (targetType) {
    case "user": return "User";
    case "client": return "Client";
    case "config":
    case "instance_config": return "Setting";
    case "signing_key": return "Signing key";
    case "instance": return "Instance";
    case "audit_log": return "Audit log";
    case "permission": return "Permission";
    case "session": return "Session";
    default: return targetType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }
}
