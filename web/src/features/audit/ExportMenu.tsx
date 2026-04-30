import { useRef, useState } from "react";
import { ChevronDownIcon } from "lucide-react";
import type { AuditState } from "./types";
import { stateToParams } from "./useUrlState";
import { useOutsideClick } from "./useOutsideClick";

export function ExportMenu({ state }: { state: AuditState }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useOutsideClick(ref, open, () => setOpen(false));

  function download(format: "csv" | "jsonl") {
    const params = stateToParams(state);
    params.set("format", format);
    window.location.assign(`/api/audit/export?${params}`);
    setOpen(false);
  }

  return (
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
            onClick={() => download("csv")}
          >
            CSV
          </button>
          <button
            type="button"
            role="menuitem"
            className="block w-full rounded-md px-2 py-1.5 text-left text-sm hover:bg-muted"
            onClick={() => download("jsonl")}
          >
            JSON
          </button>
        </div>
      )}
    </div>
  );
}
