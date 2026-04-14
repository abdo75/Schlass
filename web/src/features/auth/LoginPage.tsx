import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
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
import { ThemeToggle } from "@/components/ThemeToggle";
import { useAuth } from "./AuthContext";

export function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { login } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [retryAfterSeconds, setRetryAfterSeconds] = useState<number | null>(
    null,
  );
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorCode(null);
    setRetryAfterSeconds(null);
    setSubmitting(true);
    try {
      await login(email, password);
      void navigate("/admin", { replace: true });
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
      <ThemeToggle />
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">{t("auth.login_title")}</CardTitle>
          <CardDescription>{t("auth.login_description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={(e) => { void handleSubmit(e); }} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">{t("auth.email")}</Label>
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

            <div className="space-y-2">
              <Label htmlFor="password">{t("auth.password")}</Label>
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
              <p className="text-destructive text-sm" role="alert">
                {renderErrorMessage()}
              </p>
            )}

            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? t("auth.submitting") : t("auth.submit")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </AuthLayout>
  );
}
