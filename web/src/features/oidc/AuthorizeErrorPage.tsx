import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { AuthLayout } from "@/components/AuthLayout";

export function AuthorizeErrorPage() {
  const [params] = useSearchParams();
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const ref = params.get("ref") ?? "err_unknown";

  const copyRef = async () => {
    try {
      await navigator.clipboard.writeText(ref);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be unavailable (e.g. older browsers, embedded webviews).
      // Copy is a convenience, not essential — the ref is still displayed.
    }
  };

  return (
    <AuthLayout>
      <div className="flex min-h-screen items-center justify-center px-4">
        <div className="w-full max-w-[440px] rounded-xl border border-border bg-card p-8 text-center shadow-sm">
          <div className="mx-auto mb-4 flex h-11 w-11 items-center justify-center rounded-full bg-destructive/10 text-2xl text-destructive">
            !
          </div>
          <h1 className="mb-2 text-xl font-semibold text-foreground">
            {t("oidc.errorTitle")}
          </h1>
          <p className="mb-3 text-sm leading-relaxed text-muted-foreground">
            {t("oidc.errorBody1")}
          </p>
          <p className="mb-5 text-sm leading-relaxed text-muted-foreground">
            {t("oidc.errorBody2")}
          </p>
          <div className="mt-2 border-t border-border pt-4">
            <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">
              {t("oidc.errorRefLabel")}
            </div>
            <div className="flex items-center justify-center gap-2">
              <code
                className="rounded bg-muted px-2.5 py-1.5 font-mono text-xs text-foreground"
                data-testid="oidc-error-ref"
              >
                {ref}
              </code>
              <button
                type="button"
                onClick={() => void copyRef()}
                className="rounded border border-border px-2.5 py-1.5 text-[11px] hover:bg-muted"
              >
                {copied ? t("oidc.copied") : t("oidc.copy")}
              </button>
            </div>
            <div className="mt-2.5 text-[11px] leading-relaxed text-muted-foreground">
              {t("oidc.errorRefHint")}
            </div>
          </div>
        </div>
      </div>
    </AuthLayout>
  );
}
