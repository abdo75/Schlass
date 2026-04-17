import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { AdminLayout } from "@/components/AdminLayout";
import { Button, buttonVariants } from "@/components/ui/button";
import { useAuth } from "@/features/auth/AuthContext";

// /account page — renders the AdminLayout top-bar chrome (brand + language +
// theme + user menu) with hideSidebar=true so the admin nav is absent, then a
// centred content column with Identity hero, SECURITY card, and SESSION card.
// AuthGuard in App.tsx guarantees only authenticated users reach this route.
export function UserAccountPage() {
  const { t } = useTranslation();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [signOutErrorCode, setSignOutErrorCode] = useState<string | null>(null);

  // AuthGuard guarantees non-null; guard defensively against wiring bugs.
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

  const initial = user.email[0]?.toUpperCase() ?? "?";
  const roleLabel =
    user.role === "super_admin" ? t("role.admin") : t("role.user");

  return (
    <AdminLayout hideSidebar>
      <div className="mx-auto w-full max-w-[520px] px-5 pb-12 pt-10">

        {/* Identity hero */}
        <div className="mb-8 flex items-center gap-[14px]">
          <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full bg-primary text-[22px] font-semibold text-primary-foreground">
            {initial}
          </div>
          <div className="min-w-0">
            <div className="truncate text-[18px] font-semibold leading-tight tracking-tight">
              {user.email}
            </div>
            <div className="mt-1 text-[11.5px] text-muted-foreground">
              {roleLabel}
            </div>
          </div>
        </div>

        {/* SECURITY section label */}
        <div className="mb-[10px] px-[2px] text-[10.5px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
          {t("account.security_heading")}
        </div>

        {/* SECURITY card */}
        <div className="overflow-hidden rounded-lg border border-border bg-background">
          {/* Password row */}
          <div className="flex items-center justify-between gap-4 px-[18px] py-4">
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-semibold">
                {t("account.password_label")}
              </div>
              <div className="text-[11.5px] text-muted-foreground">
                {t("account.password_hint")}
              </div>
            </div>
            <Link
              to="/change-password"
              className={buttonVariants({
                variant: "outline",
                className: "h-8 shrink-0",
              })}
            >
              {t("account.change_button")}
            </Link>
          </div>

          <div className="h-px bg-border/60" />

          {/* 2FA row */}
          <div className="flex items-start gap-4 px-[18px] py-4">
            <div className="min-w-0 flex-1">
              <div className="mb-1 flex items-center gap-2">
                <span className="text-[13px] font-semibold">
                  {t("account.totp_label")}
                </span>
                {user.totp_enrolled_at && (
                  <span className="rounded-full bg-primary/10 px-[7px] py-[1px] text-[9.5px] font-semibold uppercase tracking-[0.05em] text-primary">
                    {t("mfa.account.enabled_badge")}
                  </span>
                )}
              </div>
              {user.totp_enrolled_at ? (
                <>
                  <div className="text-[11.5px] leading-[1.55] text-muted-foreground">
                    {t("mfa.account.enrolled_on", {
                      date: new Date(user.totp_enrolled_at).toLocaleDateString(),
                    })}
                    {"."}
                    {user.mfa?.unused_recovery_codes !== undefined && (
                      <>
                        {" "}
                        {t(
                          user.mfa.unused_recovery_codes === 1
                            ? "mfa.account.codes_remaining_one"
                            : "mfa.account.codes_remaining_other",
                          { count: user.mfa.unused_recovery_codes },
                        )}
                        {"."}
                      </>
                    )}
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground/70">
                    {t("mfa.account.reset_contact_admin")}
                  </div>
                </>
              ) : (
                <div className="text-[11.5px] leading-[1.55] text-muted-foreground">
                  {t("account.totp_placeholder")}
                </div>
              )}
            </div>
            {!user.totp_enrolled_at && (
              <Link
                to="/setup-mfa"
                className={buttonVariants({
                  variant: "outline",
                  className: "h-8 shrink-0",
                })}
              >
                {t("account.totp_setup_button")}
              </Link>
            )}
          </div>
        </div>

        {/* SESSION section label */}
        <div className="mb-[10px] mt-6 px-[2px] text-[10.5px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
          {t("account.session_heading")}
        </div>

        {/* SESSION card */}
        <div className="overflow-hidden rounded-lg border border-border bg-background">
          <div className="flex items-center justify-between gap-4 px-[18px] py-4">
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-semibold">
                {t("account.signout_label")}
              </div>
              <div className="text-[11.5px] text-muted-foreground">
                {t("account.signout_description")}
              </div>
            </div>
            <Button
              type="button"
              variant="outline"
              onClick={() => void handleSignOut()}
              className="h-8 shrink-0 border-destructive/35 text-destructive hover:bg-destructive/5 hover:text-destructive"
            >
              {t("account.sign_out")}
            </Button>
          </div>
        </div>

        {/* Sign-out error */}
        {signOutErrorCode && (
          <p className="mt-3 text-sm text-destructive" role="alert">
            {t(`errors.${signOutErrorCode}`)}
          </p>
        )}

      </div>
    </AdminLayout>
  );
}
