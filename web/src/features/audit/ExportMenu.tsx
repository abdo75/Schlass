import { useRef, useState } from "react";
import { ChevronDownIcon } from "lucide-react";
import { ApiRequestError } from "@/lib/api";
import { StepUpModal } from "./StepUpModal";
import type { AuditState } from "./types";
import { useOutsideClick } from "./useOutsideClick";

type ExportFormat = "csv" | "jsonl" | "caep";

const FORMAT_LABELS: Record<ExportFormat, string> = {
  csv: "CSV",
  jsonl: "JSON",
  caep: "CAEP SET",
};

export function ExportMenu({ state }: { state: AuditState }) {
  const [open, setOpen] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [pendingFormat, setPendingFormat] = useState<ExportFormat | null>(null);
  const [lastManifest, setLastManifest] = useState<boolean>(false);
  const ref = useRef<HTMLDivElement>(null);
  useOutsideClick(ref, open, () => setOpen(false));

  function bundleFilename(): string {
    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, "0");
    const ts = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}`;
    return `audit-log-${ts}.tar.gz`;
  }

  async function download(format: ExportFormat) {
    setOpen(false);
    setLastManifest(false);
    setPendingFormat(format);
    const response = await fetch("/api/audit/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...state, format }),
    });
    if (!response.ok) {
      const body = (await response.json()) as { error: string; message: string };
      if (response.status === 401 && body.error === "STEPUP_REQUIRED") {
        setStepUpOpen(true);
        return;
      }
      throw new ApiRequestError(response.status, body);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = bundleFilename();
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setLastManifest(true);
    setPendingFormat(null);
  }

  return (
    <>
      <div ref={ref} className="relative">
        <button
          type="button"
          aria-expanded={open}
          aria-haspopup="menu"
          aria-controls="audit-export-menu"
          className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-background px-3 text-sm font-medium hover:bg-muted"
          onClick={() => setOpen((v) => !v)}
        >
          Export
          <ChevronDownIcon className="size-3.5 text-muted-foreground" />
        </button>
        {open && (
          <div id="audit-export-menu" role="menu" aria-label="Export format" className="absolute right-0 top-10 z-40 min-w-36 rounded-lg border border-border bg-popover p-1 shadow-lg">
            {(Object.keys(FORMAT_LABELS) as ExportFormat[]).map((fmt) => (
              <button
                key={fmt}
                type="button"
                role="menuitem"
                className="block w-full rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted"
                onClick={() => void download(fmt)}
              >
                {FORMAT_LABELS[fmt]}
              </button>
            ))}
          </div>
        )}
        {lastManifest && (
          <p className="mt-1 text-xs text-muted-foreground" role="status">
            Bundle includes manifest.json with chain proof
          </p>
        )}
      </div>
      <StepUpModal
        open={stepUpOpen}
        onCancel={() => setStepUpOpen(false)}
        onVerified={() => {
          setStepUpOpen(false);
          if (pendingFormat) void download(pendingFormat);
        }}
      />
    </>
  );
}
