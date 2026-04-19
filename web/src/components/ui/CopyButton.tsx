import { useState } from "react";

// CopyButton is the project's shared clipboard-copy affordance. Icon-only
// by default, with an aria-label so screen readers announce "Copy <label>".
// On success it briefly swaps the clipboard icon for a checkmark.
//
// Used anywhere we display a secret, id, or reference that the user needs
// to paste into another app (client ID/secret reveal modals, client
// detail page's client ID row, temp-password modal, OIDC error ref, etc).

interface CopyButtonProps {
  value: string;
  /**
   * Short label used only by screen readers. Rendered as
   * `Copy <label>` in the aria-label.
   */
  label: string;
  /**
   * Optional class additions for the button's outer element.
   */
  className?: string;
  /**
   * Button size. `sm` is the default — suits inline fields; `md` matches
   * the 36px tier used next to `h-9` inputs.
   */
  size?: "sm" | "md";
}

function ClipboardIcon({ size }: { size: number }) {
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
      aria-hidden="true"
    >
      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </svg>
  );
}

function CheckIcon({ size }: { size: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

export function CopyButton({ value, label, className, size = "sm" }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const dims = size === "md" ? { box: "h-9 w-9", icon: 14 } : { box: "h-8 w-8", icon: 13 };

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API unavailable (insecure context, old browsers) — no-op.
      // Users can still select the adjacent text manually.
    }
  }

  return (
    <button
      type="button"
      onClick={() => void copy()}
      aria-label={copied ? `${label} copied` : `Copy ${label}`}
      title={copied ? "Copied" : "Copy"}
      className={
        `inline-flex shrink-0 items-center justify-center rounded-lg border border-border bg-background text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground ${dims.box} ${className ?? ""}`
      }
    >
      {copied ? <CheckIcon size={dims.icon} /> : <ClipboardIcon size={dims.icon} />}
    </button>
  );
}
