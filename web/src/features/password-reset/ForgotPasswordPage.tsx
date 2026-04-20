import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { AuthLayout } from "@/components/AuthLayout";
import { requestPasswordReset } from "./api";

export function ForgotPasswordPage() {
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
              Check your email
            </CardTitle>
          </CardHeader>
          <CardContent className="px-8 pb-6 text-center">
            <div className="mx-auto mb-[18px] grid w-11 h-11 place-items-center rounded-full bg-[oklch(0.95_0.05_155)]">
              <svg viewBox="0 0 24 24" fill="none" stroke="oklch(0.45 0.15 155)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            </div>
            <p className="text-[13.5px] text-muted-foreground leading-[1.55]">
              If an account exists for <b className="text-foreground font-medium">{submitted}</b>, a password reset link has been sent. The link expires in 30 minutes.
            </p>
          </CardContent>
          <div className="px-8 pb-6 pt-1 text-center text-[12.5px] text-muted-foreground">
            <Link to="/login" className="text-primary font-medium hover:underline">← Back to sign in</Link>
          </div>
        </Card>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout>
      <Card className="w-full overflow-hidden border-border">
        <CardHeader className="px-8 pt-8 pb-5">
          <CardTitle className="text-2xl font-semibold tracking-tight leading-tight">Reset your password</CardTitle>
          <CardDescription className="mt-2 text-[13px] leading-relaxed">
            Enter the email for your account and we'll send you a link to reset your password.
          </CardDescription>
        </CardHeader>
        <CardContent className="px-8 pb-0">
          <form onSubmit={(e) => { void handleSubmit(e); }} className="flex flex-col gap-[18px]">
            <div className="flex flex-col gap-2">
              <Label htmlFor="email" className="text-[13px] font-medium">Email</Label>
              <Input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
              />
            </div>
            <Button type="submit" className="h-9 w-full" disabled={submitting}>
              {submitting ? "Sending…" : "Send reset link"}
            </Button>
          </form>
        </CardContent>
        <div className="px-8 pb-6 pt-6 text-center text-[12.5px] text-muted-foreground">
          <Link to="/login" className="text-primary font-medium hover:underline">← Back to sign in</Link>
        </div>
      </Card>
    </AuthLayout>
  );
}
