import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, Navigate, useSearchParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AuthLayout } from "@/components/AuthLayout";
import { useAuth } from "./AuthContext";

export function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const returnTo = searchParams.get("return_to") ?? undefined;
  const { login, user, loading } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [retryAfterSeconds, setRetryAfterSeconds] = useState<number | null>(
    null,
  );
  const [submitting, setSubmitting] = useState(false);

  // Redirect already-authenticated users away from /login. Standard pattern:
  // GitHub, Okta, Linear all bounce authed users out of their login pages to
  // the default post-auth destination.
  if (loading) return null;
  if (user) {
    const dest = user.role === "super_admin" ? "/admin" : "/account";
    return <Navigate to={dest} replace />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorCode(null);
    setRetryAfterSeconds(null);
    setSubmitting(true);
    try {
      const res = await login(email, password, returnTo);
      if (res.kind === "enrollment_required") {
        void navigate("/setup-mfa", { replace: true });
        return;
      }
      if (res.kind === "challenge_required") {
        void navigate("/mfa-challenge", { replace: true, state: { email } });
        return;
      }
      // If the backend accepted a sanitized return_to, honor it verbatim —
      // it has already been validated to a same-origin /authorize URL.
      // window.location.href (not navigate) so the browser follows the full
      // URL, which for /authorize re-enters the OIDC handshake server-side.
      if (res.redirectTo) {
        window.location.href = res.redirectTo;
        return;
      }
      const destination = res.user.role === "super_admin" ? "/admin" : "/account";
      void navigate(destination, { replace: true });
    } catch (err: unknown) {
      // apiFetch throws ApiRequestError with { code, message, status,
      // retryAfterSeconds? }. See web/src/lib/api.ts for the class definition.
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      const retry =
        err &&
        typeof err === "object" &&
        "retryAfterSeconds" in err &&
        typeof (err as { retryAfterSeconds?: unknown }).retryAfterSeconds ===
          "number"
          ? (err as { retryAfterSeconds: number }).retryAfterSeconds
          : null;
      setErrorCode(code);
      setRetryAfterSeconds(retry);
    } finally {
      setSubmitting(false);
    }
  };

  // Choose the i18n key based on whether we have a retry countdown.
  // For ACCOUNT_LOCKED with a known retry window, render a minute-granularity
  // countdown via i18next's plural-aware `count` interpolation. Otherwise
  // fall back to the static "try again in a few minutes" copy.
  const renderErrorMessage = () => {
    if (!errorCode) return null;
    if (
      errorCode === "ACCOUNT_LOCKED" &&
      retryAfterSeconds != null &&
      retryAfterSeconds > 0
    ) {
      const minutes = Math.ceil(retryAfterSeconds / 60);
      return t("errors.ACCOUNT_LOCKED_WITH_RETRY", { count: minutes });
    }
    return t(`errors.${errorCode}`);
  };

  return (
    <AuthLayout>
      <Card className="w-full overflow-hidden border-border">
        <CardHeader className="px-8 pt-8 pb-5">
          <CardTitle className="text-2xl font-semibold tracking-tight leading-tight">{t("auth.login_title")}</CardTitle>
          <CardDescription className="mt-2 text-[13px] leading-relaxed">{t("auth.login_description")}</CardDescription>
        </CardHeader>
        <CardContent className="px-8 pb-7">
          <form onSubmit={(e) => { void handleSubmit(e); }} className="flex flex-col gap-[18px]">
            <div className="flex flex-col gap-2">
              <Label htmlFor="email" className="text-[13px] font-medium">{t("auth.email")}</Label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
                placeholder="admin@example.com"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>

            <div className="flex flex-col gap-2">
              <Label htmlFor="password" className="text-[13px] font-medium">{t("auth.password")}</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            {errorCode && (
              <p className="text-sm text-destructive" role="alert">
                {renderErrorMessage()}
              </p>
            )}

            <div className="border-t border-border px-8 py-7 -mx-8">
              <Button type="submit" className="h-9 w-full" disabled={submitting}>
                {submitting ? t("auth.submitting") : t("auth.submit")}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </AuthLayout>
  );
}
