import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { XIcon } from "lucide-react";
import { ApiRequestError, apiFetch } from "@/lib/api";
import { useFocusTrap } from "@/components/ui/useFocusTrap";

interface Props {
  open: boolean;
  onCancel: () => void;
  onVerified: () => void;
}

export function StepUpModal({ open, onCancel, onVerified }: Props) {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  const [recoveryMode, setRecoveryMode] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useFocusTrap(formRef, open, inputRef);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onCancel();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onCancel]);

  if (!open) return null;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await apiFetch<{ ok: boolean }>("/api/auth/stepup/challenge", {
        method: "POST",
        body: JSON.stringify(recoveryMode ? { recovery_code: recoveryCode } : { code }),
      });
      onVerified();
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(t(`errors.${err.code}`, { defaultValue: err.message }));
      } else {
        setError(t("audit.stepup.unexpected_error"));
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-foreground/35 p-4 backdrop-blur-sm" role="presentation">
      <form
        ref={formRef}
        onSubmit={(event) => void submit(event)}
        role="dialog"
        aria-modal="true"
        aria-labelledby="stepup-title"
        className="w-full max-w-sm rounded-lg border border-border bg-background p-5 shadow-xl"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="stepup-title" className="text-base font-semibold">{t("audit.stepup.title")}</h2>
            <p className="mt-1 text-sm text-muted-foreground">{t("audit.stepup.description")}</p>
          </div>
          <button
            type="button"
className="rounded-md p-1 hover:bg-muted"
            aria-label={t("audit.stepup.cancel")}
            onClick={onCancel}
          >
            <XIcon className="size-4" />
          </button>
        </div>
        <label className="mt-5 block text-sm font-medium" htmlFor="stepup-code">
          {t(recoveryMode ? "audit.stepup.recovery_label" : "audit.stepup.totp_label")}
        </label>
        <input
          ref={inputRef}
          id="stepup-code"
          className="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-ring"
          inputMode={recoveryMode ? "text" : "numeric"}
          autoComplete="one-time-code"
          value={recoveryMode ? recoveryCode : code}
          maxLength={recoveryMode ? 64 : 6}
          onChange={(event) => {
            const next = recoveryMode ? event.target.value : event.target.value.replace(/\D/g, "").slice(0, 6);
            if (recoveryMode) setRecoveryCode(next);
            else setCode(next);
          }}
        />
        {error && <p className="mt-3 text-sm text-destructive" role="alert">{error}</p>}
        <div className="mt-5 flex items-center justify-end gap-2">
          <button type="button" className="h-9 rounded-md border border-border px-3 text-sm hover:bg-muted" onClick={onCancel}>
            {t("audit.stepup.cancel")}
          </button>
          <button type="submit" disabled={submitting} className="h-9 rounded-md bg-primary px-3 text-sm font-medium text-primary-foreground disabled:opacity-60">
            {t("audit.stepup.submit")}
          </button>
        </div>
        <button
          type="button"
          data-focus-trap-ignore
          className="mt-4 text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
          onClick={() => {
            setRecoveryMode((v) => !v);
            setError("");
          }}
        >
          {t("audit.stepup.recovery_link")}
        </button>
      </form>
    </div>
  );
}
