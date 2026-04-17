import { useState } from "react";
import { useTranslation } from "react-i18next";

interface Props {
  codes: string[];
}

function CopyIcon({ size = 11 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="9" y="9" width="13" height="13" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}

function PrintIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="6 9 6 2 18 2 18 9" />
      <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" />
      <rect x="6" y="14" width="12" height="8" />
    </svg>
  );
}

function WarningIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

export function RecoveryCodesDisplay({ codes }: Props) {
  const { t } = useTranslation();
  const [flashIdx, setFlashIdx] = useState<number | null>(null);

  const copyOne = async (code: string, idx: number) => {
    await navigator.clipboard.writeText(code);
    setFlashIdx(idx);
    setTimeout(() => setFlashIdx(null), 800);
  };

  const copyAll = async () => {
    await navigator.clipboard.writeText(codes.join("\n"));
  };

  const download = () => {
    const blob = new Blob([codes.join("\n") + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "schlass-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  const print = () => {
    const w = window.open("", "_blank");
    if (!w) return;
    const pre = w.document.createElement("pre");
    pre.style.fontFamily = "monospace";
    pre.style.fontSize = "14px";
    pre.style.lineHeight = "1.6";
    pre.textContent = codes.join("\n");
    w.document.body.appendChild(pre);
    w.document.close();
    w.print();
  };

  return (
    <div className="flex flex-col gap-3">
      {/* Warning banner — mirrors TempPasswordModal's warning callout pattern */}
      <div className="flex items-center gap-[6px] rounded-[5px] border border-warning-border bg-warning px-[11px] py-2 text-warning-foreground">
        <span className="shrink-0">
          <WarningIcon />
        </span>
        <span className="text-[11px] leading-snug">
          {t("mfa.enrollment.step3_warning")}
        </span>
      </div>

      {/* Voucher grid — 2 cols × 5 rows */}
      <div className="grid grid-cols-2 gap-2">
        {codes.map((code, i) => (
          <button
            key={code}
            type="button"
            onClick={() => void copyOne(code, i)}
            aria-label={t("mfa.enrollment.copy_code_aria", { code })}
            className={[
              "group relative rounded-md bg-muted px-3 py-[14px] text-center outline-none transition-colors",
              flashIdx === i
                ? "bg-primary/20"
                : "hover:bg-primary/8 hover:shadow-[inset_0_0_0_1px_color-mix(in_oklch,var(--color-primary)_30%,transparent)]",
            ].join(" ")}
          >
            <span className="font-mono text-[15px] font-medium tracking-[0.08em] text-foreground">
              {code}
            </span>
            <span className="absolute right-[10px] top-[10px] text-primary opacity-0 transition-opacity group-hover:opacity-100">
              <CopyIcon size={12} />
            </span>
          </button>
        ))}
      </div>

      {/* Bulk actions */}
      <div className="flex gap-[6px]">
        <button
          type="button"
          onClick={() => void copyAll()}
          className="flex flex-1 items-center justify-center gap-[5px] rounded border border-border px-2 py-[7px] text-[11px] font-medium transition-colors hover:bg-muted"
        >
          <CopyIcon />
          {t("mfa.enrollment.copy_all")}
        </button>
        <button
          type="button"
          onClick={download}
          className="flex flex-1 items-center justify-center gap-[5px] rounded border border-border px-2 py-[7px] text-[11px] font-medium transition-colors hover:bg-muted"
        >
          <DownloadIcon />
          {t("mfa.enrollment.download")}
        </button>
        <button
          type="button"
          onClick={print}
          className="flex flex-1 items-center justify-center gap-[5px] rounded border border-border px-2 py-[7px] text-[11px] font-medium transition-colors hover:bg-muted"
        >
          <PrintIcon />
          {t("mfa.enrollment.print")}
        </button>
      </div>
    </div>
  );
}
