import { useTranslation } from "react-i18next";
import { AuthLayout } from "@/components/AuthLayout";
import {
  AdminLayout,
  AdminPageHeader,
  AdminPageContent,
} from "@/components/AdminLayout";
import { useAuth } from "./AuthContext";
import { ChangePasswordForm } from "./ChangePasswordForm";

export function ChangePasswordPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const forced = Boolean(user?.force_password_change);

  if (forced) {
    return (
      <AuthLayout forceChangeMode>
        <ChangePasswordForm forced />
      </AuthLayout>
    );
  }

  // Self-service mode: render inside the admin shell (sidebar + persistent top bar).
  // This route is NOT nested under /admin so we use AdminLayout directly.
  return (
    <AdminLayout>
      <AdminPageHeader title={t("auth.change_password.title_admin")} />
      <AdminPageContent>
        <div className="mx-auto w-full max-w-[448px] pt-8">
          <ChangePasswordForm forced={false} />
        </div>
      </AdminPageContent>
    </AdminLayout>
  );
}
