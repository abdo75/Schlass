import React, { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { AdminLayout, AdminPageHeader } from "@/components/AdminLayout";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/features/auth/AuthContext";
import { disableMfa } from "@/features/mfa/api";

// /account page — renders the AdminLayout top-bar chrome (brand + language +
// theme + user menu) with hideSidebar=true so the admin nav is absent, then a
// centred content column with Identity hero, SECURITY card, and SESSION card.
// AuthGuard in App.tsx guarantees only authenticated users reach this route.
export function UserAccountPage() {
  const { t } = useTranslation();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [signOutErrorCode, setSignOutErrorCode] = useState<string | null>(null);

  // Disable-MFA dialog state
  const [disableOpen, setDisableOpen] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableError, setDisableError] = useState<string | null>(null);
  const [disabling, setDisabling] = useState(false);
  const disablePasswordRef = useRef<HTMLInputElement>(null);

  const handleDisable = async () => {
    setDisabling(true);
    setDisableError(null);
    try {
      await disableMfa(disablePassword);
      // Server revoked all sessions — clear local auth state and redirect.
      await logout();
      void navigate("/login", { replace: true });
    } catch (err: unknown) {
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setDisableError(code);
      setDisabling(false);
    }
  };

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
      <AdminPageHeader />
      <div className="mx-auto w-full max-w-[520px] px-5 pb-12 pt-10">

        {/* Identity hero */}
        <div className="mb-8 flex items-center gap-[14px]">
          <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full bg-primary text-[22px] font-semibold text-primary-foreground">
            {initial}
          </div>
          <div className="min-w-0">
            <h2 className="truncate text-[18px] font-semibold leading-tight tracking-tight">
              {user.email}
            </h2>
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
                </>
              ) : (
                <div className="text-[11.5px] leading-[1.55] text-muted-foreground">
                  {t("account.totp_placeholder")}
                </div>
              )}
            </div>
            {user.totp_enrolled_at ? (
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setDisablePassword("");
                  setDisableError(null);
                  setDisableOpen(true);
                }}
                className="h-8 shrink-0 border-destructive/35 text-destructive hover:bg-destructive/5 hover:text-destructive"
              >
                {t("mfa.account.disable_button")}
              </Button>
            ) : (
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

      {/* Disable 2FA dialog */}
      {disableOpen && (
        <DisableMfaDialog
          open={disableOpen}
          onOpenChange={(open) => {
            setDisableOpen(open);
            if (!open) setDisableError(null);
          }}
          password={disablePassword}
          onPasswordChange={setDisablePassword}
          onConfirm={() => void handleDisable()}
          error={disableError}
          loading={disabling}
          passwordRef={disablePasswordRef}
        />
      )}
    </AdminLayout>
  );
}

interface DisableMfaDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  password: string;
  onPasswordChange: (v: string) => void;
  onConfirm: () => void;
  error: string | null;
  loading: boolean;
  passwordRef: React.RefObject<HTMLInputElement | null>;
}

function DisableMfaDialog({
  open,
  onOpenChange,
  password,
  onPasswordChange,
  onConfirm,
  error,
  loading,
  passwordRef,
}: DisableMfaDialogProps) {
  const { t } = useTranslation();

  useEffect(() => {
    if (!open) return;
    passwordRef.current?.focus();
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onOpenChange(false);
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open, onOpenChange, passwordRef]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-foreground/35 backdrop-blur-sm"
      onClick={() => onOpenChange(false)}
      role="dialog"
      aria-modal="true"
      aria-labelledby="disable-mfa-title"
    >
      <div
        className="w-full max-w-[440px] rounded-[14px] border border-border bg-background shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start gap-4 px-6 pt-6 pb-5">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-[10px] bg-destructive/10 text-destructive">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="size-5"
              aria-hidden="true"
            >
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" />
              <path d="M12 9v4" />
              <path d="M12 17h.01" />
            </svg>
          </div>
          <div className="flex-1 min-w-0">
            <p id="disable-mfa-title" className="text-base font-semibold">
              {t("mfa.account.disable_dialog_title")}
            </p>
            <p className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">
              {t("mfa.account.disable_dialog_description")}
            </p>
            <div className="mt-4 space-y-1.5">
              <Label htmlFor="disable-mfa-password" className="text-[12px] font-medium">
                {t("mfa.account.disable_password_label")}
              </Label>
              <Input
                id="disable-mfa-password"
                ref={passwordRef}
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => onPasswordChange(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !loading && password) onConfirm();
                }}
                className="h-8 text-sm"
                disabled={loading}
              />
              {error && (
                <p className="text-[12px] text-destructive" role="alert">
                  {t(`errors.${error}`)}
                </p>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center justify-end gap-2.5 border-t border-border bg-sidebar px-6 py-5 rounded-b-[14px]">
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={loading}
            className="group/button inline-flex shrink-0 items-center justify-center rounded-lg border border-transparent bg-clip-padding text-sm font-medium whitespace-nowrap transition-all outline-none select-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50 h-8 gap-1.5 px-2.5 border-border bg-background hover:bg-muted hover:text-foreground dark:border-input dark:bg-input/30 dark:hover:bg-input/50"
          >
            {t("mfa.account.disable_cancel")}
          </button>
          <Button
            variant="destructive"
            onClick={onConfirm}
            disabled={loading || !password}
          >
            {loading ? t("common.loading") : t("mfa.account.disable_confirm")}
          </Button>
        </div>
      </div>
    </div>
  );
}
