import { useTranslation } from "react-i18next";
import { lookupHint, type LookupResult } from "./catalog";
import type { AuditItem } from "./types";

export function ChangedValuesScalar({ event }: { event: AuditItem }) {
  const { t } = useTranslation();
  const from = event.metadata.from ?? event.metadata.old_value;
  const to = event.metadata.to ?? event.metadata.new_value;
  const key = configKeyOf(event);
  const hint = key ? lookupHint(key, from, to) : null;
  return (
    <section className="panel-block panel-block--section">
      <h4 className="panel-heading">{t("audit.panel.changedValues")}</h4>
      <DiffCard label={labelForScalar(event)} from={from} to={to} hint={hint ? t(hint.key) : undefined} />
    </section>
  );
}

export function ChangedValuesList({ event }: { event: AuditItem }) {
  const { t } = useTranslation();
  const from = Array.isArray(event.metadata.from) ? event.metadata.from.map(String) : [];
  const to = Array.isArray(event.metadata.to) ? event.metadata.to.map(String) : [];
  const added = to.filter((x) => !from.includes(x));
  const removed = from.filter((x) => !to.includes(x));
  return (
    <section className="panel-block panel-block--section">
      <h4 className="panel-heading">{t("audit.panel.changedValues")}</h4>
      <div className="panel-listdiff">
        {added.map((v) => <div key={`+${v}`} className="line added">{v}</div>)}
        {removed.map((v) => <div key={`-${v}`} className="line removed">{v}</div>)}
      </div>
    </section>
  );
}

export function ChangedValuesStacked({ event }: { event: AuditItem }) {
  const fields = Array.isArray(event.metadata.changed_fields) ? event.metadata.changed_fields : [];
  return (
    <section className="panel-block panel-block--section">
      <h4 className="panel-heading">Changed fields</h4>
      <div className="panel-diff-stack">
        {fields.map((raw) => {
          const f = raw as { field: string; from: unknown; to: unknown };
          return <DiffCard key={f.field} label={humanize(f.field)} from={f.from} to={f.to} />;
        })}
      </div>
    </section>
  );
}

export function ScopesList({ scopes }: { scopes: string[] }) {
  const { t } = useTranslation();
  return (
    <section className="panel-block panel-block--section">
      <h4 className="panel-heading">{t("audit.panel.scopesGranted")}</h4>
      <div className="panel-scopes">{(scopes ?? []).map((s) => <span key={s} className="panel-scope">{s}</span>)}</div>
    </section>
  );
}

export function ReasonCard({ result }: { result: LookupResult }) {
  const { t } = useTranslation();
  return (
    <section className="panel-block panel-block--section">
      <h4 className="panel-heading">{t("audit.panel.reason")}</h4>
      {result.fallback ? (
        <div className="panel-reason">
          <div className="panel-reason-tag">{t("audit.reason.unknown.title")}</div>
          <div className="panel-reason-label">{t("audit.reason.unknown.body")}</div>
          <div className="panel-reason-secondary">{t("audit.reason.unknown.rawLabel")} <code>{result.raw}</code></div>
        </div>
      ) : (
        <div className="panel-reason">
          <div className="panel-reason-label">{t(result.key!)}</div>
          {result.secondary && <div className="panel-reason-secondary">{result.secondary}</div>}
        </div>
      )}
    </section>
  );
}

export function WhyThisMattersAlert({ i18nKey }: { i18nKey: string }) {
  const { t } = useTranslation();
  return (
    <section className="panel-block panel-block--section">
      <div className="panel-alert">
        <h5 className="panel-alert-title">{t("audit.panel.whyThisMatters")}</h5>
        {t(i18nKey)}
      </div>
    </section>
  );
}

export function CountsGrid({ event }: { event: AuditItem }) {
  const counts = countTuples(event);
  return (
    <section className="panel-block panel-block--section">
      <div className="panel-counts">
        {counts.map(([label, value]) => (
          <div key={label}>
            <div className="panel-count-value">{value}</div>
            <div className="panel-count-label">{label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

export function ExportSummary({ event }: { event: AuditItem }) {
  return (
    <section className="panel-block panel-block--section">
      <div className="panel-count-row">
        <span className="panel-count-value">{numberValue(event.metadata.row_count)}</span>
        <span className="panel-count-value">rows exported</span>
      </div>
    </section>
  );
}

function configKeyOf(event: AuditItem): string | null {
  return event.event_type.startsWith("config.") ? event.event_type.slice("config.".length, -".changed".length) : null;
}

function DiffCard({ label, from, to, hint }: { label: string; from: unknown; to: unknown; hint?: string }) {
  return (
    <div className="panel-diff">
      <div className="panel-diff-label">{label}</div>
      <div className="panel-diff-line">
        <span className="panel-diff-old">{formatValue(from)}</span>
        <span className="panel-diff-arrow">-&gt;</span>
        <span className="panel-diff-new">{formatValue(to)}</span>
      </div>
      {hint && <div className="panel-diff-hint">{hint}</div>}
    </div>
  );
}

function countTuples(event: AuditItem): Array<[string, number]> {
  const metadata = event.metadata;
  switch (event.event_type) {
    case "password_reset.cleanup_swept":
      return [
        ["Reset tokens", numberValue(metadata.reset_rows_deleted)],
        ["Auth codes", numberValue(metadata.auth_code_rows_deleted)],
      ];
    case "user.audit_pseudonymized":
      return [["Rows updated", numberValue(metadata.rows_updated)]];
    case "client.created":
      return [
        ["Redirect URIs", numberValue(metadata.redirect_uris_count)],
        ["Scopes", Array.isArray(metadata.scopes) ? metadata.scopes.length : numberValue(metadata.scopes_count)],
        ["Grants", Array.isArray(metadata.grants) ? metadata.grants.length : numberValue(metadata.grants_count)],
      ];
    default:
      return [["Rows", numberValue(metadata.row_count ?? metadata.rows_affected)]];
  }
}

function labelForScalar(event: AuditItem): string {
  const key = configKeyOf(event);
  if (key) return humanize(key);
  if (typeof event.metadata.field === "string") return humanize(event.metadata.field);
  if (event.event_type === "client.name_updated") return "Name";
  return "Value";
}

function humanize(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : Number(value ?? 0) || 0;
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}
