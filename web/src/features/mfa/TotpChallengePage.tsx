import { useEffect, useState, type FormEvent, type JSX } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useNavigate } from "react-router-dom";
import { AuthLayout } from "@/components/AuthLayout";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/features/auth/AuthContext";
import { submitChallenge } from "./api";
import { SixDigitInput } from "./SixDigitInput";

const CHALLENGE_TTL_SECONDS = 120;

export function TotpChallengePage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const { refreshUser } = useAuth();

  const emailFromState = (location.state as { email?: string } | null)?.email ?? "";
  const [email] = useState(emailFromState);

  const [mode, setMode] = useState<"totp" | "recovery">("totp");
  const [code, setCode] = useState("");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [remaining, setRemaining] = useState(CHALLENGE_TTL_SECONDS);

  useEffect(() => {
    const id = setInterval(() => {
      setRemaining((r) => Math.max(0, r - 1));
    }, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (remaining === 0) {
      void navigate("/login", { replace: true });
    }
  }, [remaining, navigate]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (submitting) return;
    if (mode === "totp" && code.length !== 6) return;
    if (mode === "recovery" && code.length < 8) return;

    setSubmitting(true);
    setErrorCode(null);
    try {
      const { redirectTo } = await submitChallenge(
        mode === "totp" ? { code } : { recovery_code: code },
      );
      const u = await refreshUser();
      if (redirectTo) {
        window.location.href = redirectTo;
        return;
      }
      const dest = u?.role === "super_admin" ? "/admin" : "/account";
      void navigate(dest, { replace: true });
    } catch (err: unknown) {
      const ec =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setErrorCode(ec);
      setCode("");
      if (ec === "MFA_CHALLENGE_MAX_ATTEMPTS" || ec === "MFA_CHALLENGE_EXPIRED") {
        setTimeout(() => void navigate("/login", { replace: true }), 1200);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const toggleMode = () => {
    setMode((m) => (m === "totp" ? "recovery" : "totp"));
    setCode("");
    setErrorCode(null);
  };

  const mins = Math.floor(remaining / 60);
  const secs = String(remaining % 60).padStart(2, "0");
  const timeStr = `${mins}:${secs}`;

  // Render the email echo: split the i18n string around {{email}} and bold the email.
  const renderEmailEcho = () => {
    const template = t("mfa.challenge.email_echo", { email: "{{email}}" });
    const parts = template.split("{{email}}");
    const result: JSX.Element[] = [];
    parts.forEach((part, i) => {
      result.push(<span key={`p${i}`}>{part}</span>);
      if (i < parts.length - 1) {
        result.push(
          <span key={`e${i}`} className="font-semibold text-foreground">
            {email}
          </span>,
        );
      }
    });
    return result;
  };

  return (
    <AuthLayout>
      <Card className="w-full overflow-hidden border-border">
        <CardHeader className="px-[22px] pb-5 pt-[22px]">
          <CardTitle className="text-[18px] font-semibold leading-tight tracking-tight">
            {mode === "totp" ? t("mfa.challenge.title") : t("mfa.challenge.recovery_input_label")}
          </CardTitle>
          {email && (
            <CardDescription className="mt-1 text-[12px] leading-[1.5]">
              {renderEmailEcho()}
            </CardDescription>
          )}
        </CardHeader>
        <CardContent className="px-[22px] pb-[22px]">
          <form onSubmit={(e) => void handleSubmit(e)} className="flex flex-col gap-[18px]">
            {mode === "totp" ? (
              <SixDigitInput value={code} onChange={setCode} autoFocus disabled={submitting} />
            ) : (
              <input
                type="text"
                inputMode="text"
                autoComplete="one-time-code"
                maxLength={9}
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value)}
                disabled={submitting}
                aria-label={t("mfa.challenge.recovery_input_label")}
                placeholder="XXXX-XXXX"
                className="h-12 w-full rounded-[5px] border-[1.5px] border-border bg-background px-4 text-center font-mono text-[18px] tracking-[0.12em] text-foreground outline-none focus:border-primary focus:bg-primary/5"
              />
            )}

            <div className="text-center text-[10.5px] text-muted-foreground">
              {t("mfa.challenge.expires_in", { time: timeStr })}
            </div>

            {errorCode && (
              <p role="alert" className="text-sm text-destructive">
                {t(`errors.${errorCode}`)}
              </p>
            )}

            <Button
              type="submit"
              className="h-9 w-full"
              disabled={
                submitting ||
                (mode === "totp" ? code.length !== 6 : code.length < 8)
              }
            >
              {submitting
                ? t("mfa.challenge.verify_submitting")
                : t("mfa.challenge.verify_button")}
            </Button>

            <div className="text-center">
              <button
                type="button"
                onClick={toggleMode}
                className="text-[11.5px] text-primary underline underline-offset-2"
              >
                {mode === "totp"
                  ? t("mfa.challenge.use_recovery_link")
                  : t("mfa.challenge.back_to_code_link")}
              </button>
            </div>
          </form>
        </CardContent>
      </Card>
    </AuthLayout>
  );
}
