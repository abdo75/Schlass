import { useRef, useState } from "react";
import { TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
  clientId: string;
  clientSecret: string;
  onClose: () => void;
}

export function ClientSecretModal({ clientId, clientSecret, onClose }: Props) {
  const [copiedId, setCopiedId] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const timerIdRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const timerSecretRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function copy(
    value: string,
    setFlag: (b: boolean) => void,
    timerRef: React.MutableRefObject<ReturnType<typeof setTimeout> | null>,
  ) {
    void navigator.clipboard.writeText(value).then(() => {
      setFlag(true);
      if (timerRef.current !== null) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => {
        setFlag(false);
        timerRef.current = null;
      }, 1500);
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-foreground/30 backdrop-blur-sm" />
      <div className="relative z-10 w-full max-w-lg overflow-hidden rounded-xl border border-border bg-background shadow-lg">
        {/* Header */}
        <div className="flex items-start gap-4 px-7 pb-5 pt-7">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-[10px] bg-warning text-warning-foreground">
            <TriangleAlert className="size-5" />
          </div>
          <div className="flex flex-col gap-0.5">
            <span className="text-lg font-semibold leading-tight">
              Client secret
            </span>
            <span className="text-[13px] text-muted-foreground">
              Shown once. Copy it into your application&apos;s secret store
              before closing — it can&apos;t be retrieved later.
            </span>
          </div>
        </div>

        {/* Fields */}
        <div className="flex flex-col gap-3.5 px-7 pb-5">
          <Field
            label="Client ID"
            value={clientId}
            copied={copiedId}
            onCopy={() => copy(clientId, setCopiedId, timerIdRef)}
          />
          <Field
            label="Client secret"
            value={clientSecret}
            highlight
            copied={copiedSecret}
            onCopy={() => copy(clientSecret, setCopiedSecret, timerSecretRef)}
          />
        </div>

        {/* Footer */}
        <div className="flex justify-end px-7 py-6">
          <Button variant="default" onClick={onClose}>
            Done
          </Button>
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  copied,
  highlight,
  onCopy,
}: {
  label: string;
  value: string;
  copied: boolean;
  highlight?: boolean;
  onCopy: () => void;
}) {
  return (
    <div>
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="flex gap-2">
        <code
          className={`flex-1 break-all rounded-lg border px-3 py-2 text-[13px] font-mono${
            highlight
              ? " border-warning-border bg-warning text-warning-foreground"
              : " border-border bg-muted text-foreground"
          }`}
        >
          {value}
        </code>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-9 shrink-0"
          onClick={onCopy}
        >
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </div>
  );
}
