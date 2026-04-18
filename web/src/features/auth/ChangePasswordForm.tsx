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
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { changePassword } from "./api";
import { useAuth } from "./AuthContext";

interface ChangePasswordFormProps {
  forced: boolean;
}

export function ChangePasswordForm({ forced }: ChangePasswordFormProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { refreshUser, user } = useAuth();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (newPassword !== confirmPassword) {
      setErrorMessage(t("auth.password_mismatch"));
      return;
    }

    setSubmitting(true);
    try {
      const { redirectTo } = await changePassword(currentPassword, newPassword);
      // refreshUser re-reads /api/me so the cleared force_password_change flag
      // is visible to AuthGuard; otherwise it would bounce us back here.
      const refreshedUser = await refreshUser();
      // If login threaded a return_to through this forced-password-change
      // flow, the backend emits it as redirect_to — follow verbatim (it is
      // already a sanitized same-origin /authorize URL).
      if (redirectTo) {
        window.location.href = redirectTo;
        return;
      }
      // Use the refreshed user's role for navigation, not the pre-refresh
      // closure value — that would be incorrect if password-change ever
      // triggers a role mutation upstream.
      const dest =
        refreshedUser?.role === "super_admin" ? "/admin/users" : "/account";
      void navigate(dest, { replace: true });
    } catch (err: unknown) {
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setErrorMessage(t(`errors.${code}`));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Card className="w-full">
      <form
        onSubmit={(e) => {
          void handleSubmit(e);
        }}
      >
        <CardHeader>
          <CardTitle className={forced ? "text-2xl" : "text-xl"}>
            {t("auth.change_password.title_card")}
          </CardTitle>
          <CardDescription>
            {forced
              ? t("auth.change_password.forced.subtitle")
              : t("auth.change_password.self_service.subtitle")}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="current-password">
              {t("auth.current_password")}
            </Label>
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="new-password">{t("auth.new_password")}</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
            <p className="text-[13px] text-muted-foreground">
              {t("setup.passwordHint")}
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirm-new-password">
              {t("auth.confirm_new_password")}
            </Label>
            <Input
              id="confirm-new-password"
              type="password"
              autoComplete="new-password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>

          {errorMessage && (
            <p className="text-destructive text-sm" role="alert">
              {errorMessage}
            </p>
          )}
        </CardContent>
        <CardFooter className="border-t border-border pt-4">
          {forced ? (
            <Button
              type="submit"
              className="h-9 w-full"
              disabled={submitting}
            >
              {submitting
                ? t("auth.submitting_change_password")
                : t("auth.change_password.confirm")}
            </Button>
          ) : (
            <div className="flex w-full justify-end gap-3">
              <Button
                type="button"
                variant="outline"
                className="h-8"
                onClick={() => {
                  const dest =
                    user?.role === "super_admin" ? "/admin/users" : "/account";
                  void navigate(dest, { replace: true });
                }}
              >
                {t("users.confirm.cancel")}
              </Button>
              <Button
                type="submit"
                className="h-8"
                disabled={submitting}
              >
                {submitting
                  ? t("auth.submitting_change_password")
                  : t("auth.change_password.confirm")}
              </Button>
            </div>
          )}
        </CardFooter>
      </form>
    </Card>
  );
}
