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
import { changePassword } from "./api";
import { useAuth } from "./AuthContext";

export function ChangePasswordPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { refreshUser } = useAuth();

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
      await changePassword(currentPassword, newPassword);
      // refreshUser re-reads /api/me so the cleared force_password_change flag
      // is visible to AuthGuard; otherwise it would bounce us back here.
      await refreshUser();
      void navigate("/admin", { replace: true });
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
    <AuthLayout>
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">
            {t("auth.change_password_title")}
          </CardTitle>
          <CardDescription>
            {t("auth.change_password_description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(e) => {
              void handleSubmit(e);
            }}
            className="space-y-4"
          >
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

            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting
                ? t("auth.submitting_change_password")
                : t("auth.submit_change_password")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </AuthLayout>
  );
}
