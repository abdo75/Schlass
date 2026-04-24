import { useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { AuthLayout } from "@/components/AuthLayout";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { CopyButton } from "@/components/ui/CopyButton";

export function AuthorizeErrorPage() {
  const [params] = useSearchParams();
  const { t } = useTranslation();
  const ref = params.get("ref") ?? "err_unknown";

  return (
    <AuthLayout>
      <Card className="w-full overflow-hidden border-border text-center">
        <CardHeader className="justify-items-center px-8 pt-8 pb-4">
          <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-full bg-destructive/10 text-2xl font-semibold text-destructive">
            !
          </div>
          <CardTitle className="text-2xl font-semibold tracking-tight leading-tight">
            {t("oidc.errorTitle")}
          </CardTitle>
          <CardDescription className="mt-2 text-[13px] leading-relaxed">
            {t("oidc.errorBody1")}
          </CardDescription>
        </CardHeader>
        <CardContent className="px-8 pb-7">
          <p className="mb-5 text-[13px] leading-relaxed text-muted-foreground">
            {t("oidc.errorBody2")}
          </p>
          <div className="border-t border-border pt-4">
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
              <CopyButton value={ref} label="error reference" />
              <span className="sr-only">{t("oidc.copy")}</span>
            </div>
            <div className="mt-2.5 text-[11px] leading-relaxed text-muted-foreground">
              {t("oidc.errorRefHint")}
            </div>
          </div>
        </CardContent>
      </Card>
    </AuthLayout>
  );
}
