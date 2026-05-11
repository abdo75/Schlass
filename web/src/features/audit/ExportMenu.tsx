import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ChevronDownIcon } from "lucide-react";
import { toast } from "sonner";
import { ApiRequestError } from "@/lib/api";
import { StepUpModal } from "./StepUpModal";
import type { AuditState } from "./types";
import { useOutsideClick } from "./useOutsideClick";

type ExportFormat = "csv" | "jsonl" | "caep";

const FORMATS: ExportFormat[] = ["csv", "jsonl", "caep"];

export function ExportMenu({ state }: { state: AuditState }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [pendingFormat, setPendingFormat] = useState<ExportFormat | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  // fetchLock guards against concurrent network requests (rapid double-click)
  // independently from pendingFormat, which we keep set across the step-up
  // round-trip so onVerified can resume the download.
  const fetchLock = useRef(false);
  useOutsideClick(ref, open, () => setOpen(false));
  const pending = pendingFormat !== null;

  function bundleFilename(format: ExportFormat): string {
    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, "0");
    const ts = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}`;
    return `audit-log-${ts}-${format}.tar.gz`;
  }

  async function download(format: ExportFormat) {
    if (fetchLock.current) return;
    fetchLock.current = true;
    setOpen(false);
    setPendingFormat(format);
    try {
      const response = await fetch("/api/audit/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...state, format }),
      });
      if (!response.ok) {
        const body = (await response.json()) as { error: string; message: string };
        if (response.status === 401 && body.error === "STEPUP_REQUIRED") {
          // Keep pendingFormat set so the verified callback can resume the
          // download with the same format. StepUp cancellation clears it.
          fetchLock.current = false;
          setStepUpOpen(true);
          return;
        }
        throw new ApiRequestError(response.status, body);
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = bundleFilename(format);
      document.body.append(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success(t("audit.export.succeeded"));
      setPendingFormat(null);
    } catch (err) {
      const message = err instanceof ApiRequestError && err.message
        ? `${t("audit.export.failed")} ${err.message}`
        : t("audit.export.failed");
      toast.error(message);
      setPendingFormat(null);
    } finally {
      fetchLock.current = false;
    }
  }

  return (
    <>
      <div ref={ref} className="relative">
        <button
          type="button"
          aria-expanded={open}
          aria-haspopup="menu"
          aria-controls="audit-export-menu"
          disabled={pending}
          className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-background px-3 text-sm font-medium hover:bg-muted disabled:cursor-not-allowed disabled:opacity-60"
          onClick={() => setOpen((v) => !v)}
        >
          {pending ? t("audit.export.started") : t("audit.export.button")}
          <ChevronDownIcon className="size-3.5 text-muted-foreground" />
        </button>
        {open && !pending && (
          <div id="audit-export-menu" role="menu" aria-label={t("audit.export.menuLabel")} className="absolute right-0 top-10 z-40 min-w-36 rounded-lg border border-border bg-popover p-1 shadow-lg">
            {FORMATS.map((fmt) => (
              <button
                key={fmt}
                type="button"
                role="menuitem"
                className="block w-full rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted"
                onClick={() => void download(fmt)}
              >
                {t(`audit.export.format.${fmt}`)}
              </button>
            ))}
          </div>
        )}
      </div>
      <StepUpModal
        open={stepUpOpen}
        onCancel={() => {
          setStepUpOpen(false);
          setPendingFormat(null);
        }}
        onVerified={() => {
          setStepUpOpen(false);
          if (pendingFormat) {
            const fmt = pendingFormat;
            setPendingFormat(null);
            void download(fmt);
          }
        }}
      />
    </>
  );
}
