import { useRef, useState } from "react";
import { ChevronDownIcon } from "lucide-react";
import { ApiRequestError } from "@/lib/api";
import { StepUpModal } from "./StepUpModal";
import type { AuditState } from "./types";
import { useOutsideClick } from "./useOutsideClick";

export function ExportMenu({ state }: { state: AuditState }) {
  const [open, setOpen] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [pendingFormat, setPendingFormat] = useState<"csv" | "jsonl" | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  useOutsideClick(ref, open, () => setOpen(false));

  async function download(format: "csv" | "jsonl") {
    setOpen(false);
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
    a.download = `audit-log.${format === "csv" ? "csv" : "jsonl"}`;
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setPendingFormat(null);
  }

  return (
    <>
      <div ref={ref} className="relative">
        <button
          type="button"
          aria-expanded={open}
          className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-background px-3 text-sm font-medium hover:bg-muted"
          onClick={() => setOpen((v) => !v)}
        >
          Export
          <ChevronDownIcon className="size-3.5 text-muted-foreground" />
        </button>
        {open && (
          <div role="menu" className="absolute right-0 top-10 z-40 min-w-32 rounded-lg border border-border bg-popover p-1 shadow-lg">
            <button
              type="button"
              role="menuitem"
              className="block w-full rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted"
              onClick={() => void download("csv")}
            >
              CSV
            </button>
            <button
              type="button"
              role="menuitem"
              className="block w-full rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted"
              onClick={() => void download("jsonl")}
            >
              JSON
            </button>
          </div>
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
