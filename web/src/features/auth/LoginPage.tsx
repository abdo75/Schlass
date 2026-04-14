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
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorCode(null);
    setSubmitting(true);
    try {
      await login(email, password);
      navigate("/admin", { replace: true });
    } catch (err: unknown) {
      // apiFetch throws ApiRequestError with a `code` field (not `error`).
      // See web/src/lib/api.ts for the class definition.
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setErrorCode(code);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthLayout>
      <ThemeToggle />
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">{t("auth.login_title")}</CardTitle>
          <CardDescription>{t("login.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
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
                {t(`errors.${errorCode}`)}
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
