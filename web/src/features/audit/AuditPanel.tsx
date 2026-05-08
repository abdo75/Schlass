import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { useFocusTrap } from "@/components/ui/useFocusTrap";
import { lookupAlert, lookupReason, renderSentence, severity } from "./catalog";
import { ChangedValuesList, ChangedValuesScalar, ChangedValuesStacked, CountsGrid, ExportSummary, ReasonCard, ScopesList, WhyThisMattersAlert } from "./AuditPanelModules";
import { OutcomeChip, ParticipantsSection, SeverityBadge, TechnicalDetails, Timestamp } from "./AuditPanelHelpers";
import type { AuditItem, Outcome } from "./types";

const PANEL_TITLE_ID = "audit-panel-title";

export function AuditPanel({
  event,
  onClose,
  onActorFilter,
  onTargetFilter,
  onTargetTypeFilter,
  onEventTypeFilter,
  onOutcomeFilter,
}: {
  event: AuditItem;
  onClose: () => void;
  onActorFilter?: (actor: string) => void;
  onTargetFilter?: (target: { target_type: string; target_id: string }) => void;
  onTargetTypeFilter?: (targetType: string) => void;
  onEventTypeFilter?: (eventType: string) => void;
  onOutcomeFilter?: (outcome: Outcome) => void;
}) {
  const { t, i18n } = useTranslation();
  const sentence = renderSentence(event.event_type, event.metadata, event.actor_display, event.target_display);
  const sev = severity(event.event_type, event.metadata);
  const alertKey = lookupAlert(event.event_type);
  const panelRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  useFocusTrap(panelRef, true, closeRef);

  useEffect(() => {
    function onKeyDown(key: KeyboardEvent) {
      if (key.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div className="audit-panel-overlay" onClick={onClose} role="presentation" data-testid="audit-panel-backdrop">
      <aside
        ref={panelRef}
        className="audit-panel"
        role="dialog"
        aria-modal="true"
        aria-label={t("audit.panel.eventDetail")}
        aria-describedby={PANEL_TITLE_ID}
        onClick={(click) => click.stopPropagation()}
      >
        <button ref={closeRef} className="panel-close" onClick={onClose} aria-label={t("audit.panel.close")} type="button">×</button>
          <section className="panel-block panel-block--hero">
            <div className="panel-eyebrow">{t("audit.panel.event")}</div>
            <div className="panel-badges">
              <OutcomeChip outcome={event.outcome} onFilter={onOutcomeFilter} />
              {sev === "critical" && <SeverityBadge>{t("audit.severity.critical")}</SeverityBadge>}
            </div>
            <p id={PANEL_TITLE_ID} className="panel-sentence">{sentence.text}</p>
            <Timestamp at={event.created_at} locale={i18n.language} />
          </section>
          <ActionsBlock event={event} />
          <ParticipantsSection event={event} onActorFilter={onActorFilter} onTargetFilter={onTargetFilter} onTargetTypeFilter={onTargetTypeFilter} />
        <ConditionalContent event={event} alertKey={alertKey} />
        <TechnicalDetails event={event} onEventTypeFilter={onEventTypeFilter} onTargetFilter={onTargetFilter} />
      </aside>
    </div>
  );
}

function ActionsBlock({ event }: { event: AuditItem }) {
  const { t } = useTranslation();

  async function writeClipboard(text: string, successKey: string) {
    try {
      if (!navigator.clipboard) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(text);
      toast.success(t(successKey));
    } catch {
      toast.error(t("audit.panel.copyFailed"));
    }
  }

  function copyLink() {
    void writeClipboard(`${window.location.origin}/admin/audit?event=${event.id}`, "audit.panel.linkCopied");
  }

  function copyData() {
    void writeClipboard(JSON.stringify(event, null, 2), "audit.panel.dataCopied");
  }

  function exportData() {
    let url: string | null = null;
    try {
      const blob = new Blob([JSON.stringify(event, null, 2)], { type: "application/json" });
      url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${event.id}.json`;
      document.body.append(link);
      link.click();
      link.remove();
      toast.success(t("audit.panel.dataExported"));
    } catch {
      toast.error(t("audit.panel.exportFailed"));
    } finally {
      if (url) URL.revokeObjectURL(url);
    }
  }

  return (
    <section className="panel-block panel-block--actions">
      <div className="panel-actions">
        <button className="panel-btn" type="button" onClick={copyLink}><CopyIcon />{t("audit.panel.copyLink")}</button>
        <button className="panel-btn" type="button" onClick={copyData}><CopyIcon />{t("audit.panel.copyData")}</button>
        <button className="panel-btn" type="button" onClick={exportData}><DownloadIcon />{t("audit.panel.exportData")}</button>
      </div>
    </section>
  );
}

function CopyIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="9" y="9" width="13" height="13" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}

function ConditionalContent({ event, alertKey }: { event: AuditItem; alertKey: string | null }) {
  const reason = lookupReason(event.event_type, event.metadata);
  return (
    <>
      {(event.event_type === "client.name_updated" || event.event_type.startsWith("config.")) && <ChangedValuesScalar event={event} />}
      {["client.redirect_uris_updated", "client.scopes_updated", "client.grants_updated"].includes(event.event_type) && <ChangedValuesList event={event} />}
      {event.event_type === "user.updated" && <ChangedValuesStacked event={event} />}
      {["oidc.authorize.succeeded", "oidc.code.exchanged", "oidc.token.refreshed"].includes(event.event_type) && (
        <ScopesList scopes={Array.isArray(event.metadata?.scopes) ? event.metadata.scopes.filter((s): s is string => typeof s === "string") : []} />
      )}
      {(reason.key || reason.raw) && <ReasonCard result={reason} />}
      {alertKey && <WhyThisMattersAlert i18nKey={alertKey} />}
      {["password_reset.cleanup_swept", "user.audit_pseudonymized", "client.created"].includes(event.event_type) && <CountsGrid event={event} />}
      {event.event_type === "audit.exported" && <ExportSummary event={event} />}
    </>
  );
}
