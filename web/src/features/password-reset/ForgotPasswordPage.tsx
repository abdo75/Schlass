import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useTranslation, Trans } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { AuthLayout } from "@/components/AuthLayout";
import { requestPasswordReset } from "./api";

export function ForgotPasswordPage() {
  const { t } = useTranslation();
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await requestPasswordReset(email);
      setSubmitted(email);
    } catch {
      // Backend always returns 200 even on no-match; treat errors as
      // success so enumeration isn't leaked by the UI either.
      setSubmitted(email);
    } finally {
      setSubmitting(false);
    }
  }

  if (submitted) {
    return (
      <AuthLayout>
        <Card className="w-full overflow-hidden border-border">
          <CardHeader className="px-8 pt-8 pb-5 text-center">
            <CardTitle className="text-2xl font-semibold tracking-tight leading-tight">
              {t("password_reset.forgot.sent_title")}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-8 pb-6 text-center">
            <div className="mx-auto mb-[18px] grid w-11 h-11 place-items-center rounded-full bg-[oklch(0.95_0.05_155)]">
              <svg viewBox="0 0 24 24" fill="none" stroke="oklch(0.45 0.15 155)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            </div>
            <p className="text-[13.5px] text-muted-foreground leading-[1.55]">
              <Trans
                i18nKey="password_reset.forgot.sent_body"
                values={{ email: submitted }}
                components={{ 1: <b className="text-foreground font-medium" /> }}
              />
            </p>
          </CardContent>
          <div className="px-8 pb-6 pt-1 text-center text-[12.5px] text-muted-foreground">
            <Link to="/login" className="text-primary font-medium hover:underline">
              {t("password_reset.forgot.back_to_login")}
            </Link>
          </div>
        </Card>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <Card className="w-full overflow-hidden border-border">
        <CardHeader className="px-8 pt-8 pb-5">
          <CardTitle className="text-2xl font-semibold tracking-tight leading-tight">
            {t("password_reset.forgot.title")}
          </CardTitle>
          <CardDescription className="mt-2 text-[13px] leading-relaxed">
            {t("password_reset.forgot.description")}
          </CardDescription>
        </CardHeader>
        <CardContent className="px-8 pb-0">
          <form onSubmit={(e) => { void handleSubmit(e); }} className="flex flex-col gap-[18px]">
            <div className="flex flex-col gap-2">
              <Label htmlFor="email" className="text-[13px] font-medium">
                {t("password_reset.forgot.email_label")}
              </Label>
              <Input
                id="email"
                type="email"
                required
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder={t("password_reset.forgot.email_placeholder")}
              />
            </div>
            <Button type="submit" className="h-9 w-full" disabled={submitting}>
              {submitting ? t("password_reset.forgot.submitting") : t("password_reset.forgot.submit")}
            </Button>
          </form>
        </CardContent>
        <div className="px-8 pb-6 pt-6 text-center text-[12.5px] text-muted-foreground">
          <Link to="/login" className="text-primary font-medium hover:underline">
            {t("password_reset.forgot.back_to_login")}
          </Link>
        </div>
      </Card>
    </AuthLayout>
  );
}
