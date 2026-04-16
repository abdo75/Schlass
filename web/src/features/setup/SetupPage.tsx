import { useState, useEffect, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
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
import { apiFetch, ApiRequestError } from "@/lib/api";
import { AuthLayout } from "@/components/AuthLayout";

export function SetupPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [setupAvailable, setSetupAvailable] = useState(false);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [instanceName, setInstanceName] = useState("");

  useEffect(() => {
    apiFetch<{ setup_required: boolean }>("/api/setup")
      .then(() => {
        setSetupAvailable(true);
        setLoading(false);
      })
      .catch((err) => {
        if (err instanceof ApiRequestError && err.status === 404) {
          void navigate("/login", { replace: true });
        } else {
          setError(t("setup.error.setupCheckFailed"));
          setLoading(false);
        }
      });
  }, [navigate, t]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError(t("errors.passwordMismatch"));
      return;
    }

    setSubmitting(true);
    try {
      const result = await apiFetch<{ redirect: string }>("/api/setup", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          confirm_password: confirmPassword,
          instance_name: instanceName,
        }),
      });
      void navigate(result.redirect, { replace: true });
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(t(`errors.${err.code}`, { defaultValue: err.message }));
      } else {
        setError(t("errors.unexpected"));
      }
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-muted-foreground">{t("common.loading")}</p>
      </div>
    );
  }

  if (!setupAvailable) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-destructive">{error}</p>
      </div>
    );
  }

  return (
    <AuthLayout>
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">{t("setup.title")}</CardTitle>
          <CardDescription>{t("setup.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={(e) => { void handleSubmit(e); }} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="instance-name">{t("setup.instanceName")}</Label>
              <Input
                id="instance-name"
                type="text"
                placeholder={t("setup.instanceNamePlaceholder")}
                value={instanceName}
                onChange={(e) => setInstanceName(e.target.value)}
                required
                maxLength={128}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">{t("setup.adminEmail")}</Label>
              <Input
                id="email"
                type="email"
                placeholder={t("setup.emailPlaceholder")}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">{t("setup.password")}</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={12}
              />
              <p className="text-xs text-muted-foreground">
                {t("setup.passwordHint")}
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirm-password">{t("setup.confirmPassword")}</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>

            {error && (
              <p className="text-sm text-destructive">{error}</p>
            )}

            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? t("setup.submitting") : t("setup.submit")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </AuthLayout>
  );
}
