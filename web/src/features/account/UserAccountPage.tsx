import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router-dom";
import { Button, buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AuthLayout } from "@/components/AuthLayout";
import { useAuth } from "@/features/auth/AuthContext";

// Placeholder end-user portal. Sprint 6 will flesh out self-service TOTP
// enrollment, session list, and recovery; today this page just confirms the
// user is signed in, links to the existing ChangePasswordPage, and hosts a
// visible sign-out so the user is never stuck on a landing page they cannot
// leave.
//
// Reuses AuthLayout for visual consistency with /login and /change-password.
// When Sprint 6 designs the real portal, this component will be replaced.
export function UserAccountPage() {
  const { t } = useTranslation();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [signOutErrorCode, setSignOutErrorCode] = useState<string | null>(null);

  // AuthGuard in App.tsx guarantees user is non-null here. If it is ever null
  // we are in a wiring bug; render nothing rather than crash.
  if (!user) return null;

  const handleSignOut = async () => {
    setSignOutErrorCode(null);
    try {
      await logout();
      void navigate("/login", { replace: true });
    } catch (err: unknown) {
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setSignOutErrorCode(code);
    }
  };

  return (
    <AuthLayout>
      <Card className="w-full overflow-hidden border-border">
        <CardHeader className="px-8 pt-8 pb-5">
          <CardTitle className="text-2xl font-semibold tracking-tight leading-tight">
            {t("account.title")}
          </CardTitle>
          <CardDescription className="mt-2 text-[13px] leading-relaxed">
            {t("account.subtitle", { email: user.email })}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-6 px-8 pb-7">
          <section className="flex flex-col gap-2">
            <h2 className="text-sm font-semibold">{t("account.password_heading")}</h2>
            <p className="text-[13px] leading-relaxed text-muted-foreground">
              {t("account.password_hint")}
            </p>
            <Link
              to="/change-password"
              className={buttonVariants({ variant: "outline" }) + " h-9 self-start"}
            >
              {t("account.change_password")}
            </Link>
          </section>
          <section className="flex flex-col gap-2">
            <h2 className="text-sm font-semibold">{t("account.totp_heading")}</h2>
            <p className="text-[13px] leading-relaxed text-muted-foreground">
              {t("account.totp_placeholder")}
            </p>
          </section>
          {signOutErrorCode && (
            <p className="text-sm text-destructive" role="alert">
              {t(`errors.${signOutErrorCode}`)}
            </p>
          )}
          <div className="border-t border-border px-8 py-7 -mx-8">
            <Button
              type="button"
              variant="outline"
              className="h-9 w-full"
              onClick={() => void handleSignOut()}
            >
              {t("account.sign_out")}
            </Button>
          </div>
        </CardContent>
      </Card>
    </AuthLayout>
  );
}
