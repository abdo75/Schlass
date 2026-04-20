import { useState, useEffect, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { AuthLayout } from "@/components/AuthLayout";
import { confirmPasswordReset, validateResetToken } from "./api";

type State = "loading" | "form" | "invalid" | "success";

export function ResetPasswordPage() {
  const { token = "" } = useParams();
  const navigate = useNavigate();
  const [state, setState] = useState<State>("loading");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!token) {
        if (!cancelled) setState("invalid");
        return;
      }
      try {
        await validateResetToken(token);
        if (!cancelled) setState("form");
      } catch {
        // Collapse every error (INVALID_TOKEN, network, 5xx) into the
        // invalid-link card. We cannot safely render the form on
        // anything other than a confirmed-valid token.
        if (!cancelled) setState("invalid");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setErrorCode(null);
    if (password !== confirm) {
      setErrorCode("PASSWORD_MISMATCH");
      return;
    }
    setSubmitting(true);
    try {
      await confirmPasswordReset(token, password);
      setState("success");
    } catch (err: unknown) {
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      if (code === "INVALID_TOKEN") {
        setState("invalid");
      } else {
        setErrorCode(code);
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (state === "loading") {
    return (
      <AuthLayout>
        <div
          className="w-full rounded-xl border p-7 pt-8 text-center"
          role="status"
          aria-live="polite"
        >
          <div className="mx-auto mb-3.5 grid w-11 h-11 place-items-center rounded-full bg-muted">
            <svg
              viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
              className="w-[22px] h-[22px] animate-spin text-muted-foreground"
              aria-hidden="true"
            >
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
          </div>
          <h4 className="text-[16px] font-semibold mb-2">Checking reset link…</h4>
          <p className="text-[13px] text-muted-foreground leading-[1.55]">
            One moment while we verify this link is still valid.
          </p>
        </div>
      </AuthLayout>
    );
  }

  if (state === "invalid") {
    return (
      <AuthLayout>
        <div
          className="w-full rounded-xl border p-7 pt-8 text-center"
          style={{ background: "oklch(0.98 0.01 30)", borderColor: "oklch(0.9 0.07 30)" }}
        >
          <div
            className="mx-auto mb-3.5 grid w-11 h-11 place-items-center rounded-full"
            style={{ background: "oklch(0.94 0.07 30)" }}
          >
            <svg
              viewBox="0 0 24 24" fill="none" stroke="oklch(0.55 0.17 30)"
              strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
              className="w-[22px] h-[22px]"
            >
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          </div>
          <h4 className="text-[16px] font-semibold mb-2">This reset link is no longer valid</h4>
          <p className="text-[13px] text-muted-foreground mb-5 leading-[1.55]">
            Reset links expire after 30 minutes and can only be used once. Request a new link to continue.
          </p>
          <Button onClick={() => { void navigate("/forgot-password"); }} className="h-9 max-w-[240px] mx-auto block">
            Request a new link
          </Button>
        </div>
      </AuthLayout>
    );
  }

  if (state === "success") {
    return (
      <AuthLayout>
        <Card className="w-full overflow-hidden border-border">
          <CardHeader className="px-8 pt-8 pb-5 text-center">
            <CardTitle className="text-2xl font-semibold tracking-tight leading-tight">
              Password reset
            </CardTitle>
          </CardHeader>
          <CardContent className="px-8 pb-6 text-center">
            <div className="mx-auto mb-[18px] grid w-11 h-11 place-items-center rounded-full bg-[oklch(0.95_0.05_155)]">
              <svg
                viewBox="0 0 24 24" fill="none" stroke="oklch(0.45 0.15 155)"
                strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
                className="w-5 h-5"
              >
                <polyline points="20 6 9 17 4 12" />
              </svg>
            </div>
            <p className="text-[13.5px] text-muted-foreground leading-[1.55] mb-5">
              Your password has been updated. Any sessions or tokens issued before this moment have been signed out.
            </p>
            <Button onClick={() => { void navigate("/login"); }} className="h-9 max-w-[240px] mx-auto block">
              Sign in
            </Button>
          </CardContent>
        </Card>
      </AuthLayout>
    );
  }

  // form state
  return (
    <AuthLayout>
      <Card className="w-full overflow-hidden border-border">
        <CardHeader className="px-8 pt-8 pb-5">
          <CardTitle className="text-2xl font-semibold tracking-tight leading-tight">Set a new password</CardTitle>
          <CardDescription className="mt-2 text-[13px] leading-relaxed">
            At least 12 characters, with an uppercase letter and a digit.
          </CardDescription>
        </CardHeader>
        <CardContent className="px-8 pb-6">
          <form onSubmit={(e) => { void handleSubmit(e); }} className="flex flex-col gap-[18px]">
            <div className="flex flex-col gap-2">
              <Label htmlFor="new-pw" className="text-[13px] font-medium">New password</Label>
              <Input id="new-pw" type="password" required
                autoComplete="new-password"
                value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="confirm-pw" className="text-[13px] font-medium">Confirm new password</Label>
              <Input id="confirm-pw" type="password" required
                autoComplete="new-password"
                value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </div>
            {errorCode && (
              <p className="text-sm text-destructive" role="alert">
                {errorCode === "PASSWORD_MISMATCH"
                  ? "Passwords don't match."
                  : errorCode === "PASSWORD_POLICY_VIOLATION"
                  ? "Password does not meet the policy (at least 12 characters, with an uppercase letter and a digit)."
                  : "Unable to reset password."}
              </p>
            )}
            <Button type="submit" className="h-9 w-full" disabled={submitting}>
              {submitting ? "Resetting…" : "Reset password"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </AuthLayout>
  );
}
