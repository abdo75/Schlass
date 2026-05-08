import { useTranslation } from "react-i18next";
import { NumberInput } from "@/components/ui/NumberInput";
import type { AuditLogSettings } from "./api";

interface Props {
  value: AuditLogSettings;
  onChange: (next: AuditLogSettings) => void;
  dirtyKeys: Set<keyof AuditLogSettings>;
}

function DirtyDot({ show }: { show: boolean }) {
  if (!show) return null;
  return <span className="ml-2 inline-block h-1.5 w-1.5 rounded-full bg-primary align-middle" aria-hidden="true" />;
}

export function AuditLogTab({ value, onChange, dirtyKeys }: Props) {
  const { t } = useTranslation();
  const viewLogging = t("settings.audit.viewLogging");
  const exportCap = t("settings.audit.exportCap");
  return (
    <div className="mb-4 overflow-hidden rounded-xl border border-border bg-background">
      <div className="px-6 pb-1 pt-5">
        <h3 className="text-[15px] font-semibold">{t("settings.audit.heading")}</h3>
        <p className="mt-1 text-[13px] leading-relaxed text-muted-foreground">
          {t("settings.audit.description")}
        </p>
      </div>
      <div className="flex flex-col gap-[14px] px-6 pb-5 pt-[14px]">
        <label className="grid grid-cols-[1fr_auto] items-center gap-5">
          <span className="text-[13.5px] font-medium">
            {viewLogging}
            <DirtyDot show={dirtyKeys.has("audit_view_logging_enabled")} />
          </span>
          <input
            type="checkbox"
            role="switch"
            checked={value.audit_view_logging_enabled}
            onChange={(event) => onChange({ ...value, audit_view_logging_enabled: event.target.checked })}
            aria-label={viewLogging}
          />
        </label>
        <div className="grid grid-cols-[1fr_auto] items-center gap-5">
          <span className="text-[13.5px] font-medium">
            {exportCap}
            <DirtyDot show={dirtyKeys.has("audit_export_max_rows")} />
          </span>
          <NumberInput
            value={value.audit_export_max_rows}
            min={0}
            max={1_000_000}
            ariaLabel={exportCap}
            onChange={(n) => onChange({ ...value, audit_export_max_rows: n })}
          />
        </div>
      </div>
    </div>
  );
}
