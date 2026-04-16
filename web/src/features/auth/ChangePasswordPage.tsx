import { useTranslation } from "react-i18next";
import { AuthLayout } from "@/components/AuthLayout";
import {
  AdminSidebar,
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

  // Self-service mode: render inside the admin shell.
  // This route is NOT nested under /admin so we compose the shell manually.
  return (
    <div className="flex min-h-screen bg-sidebar">
      <AdminSidebar />
      <main className="flex min-w-0 flex-1 flex-col bg-background">
        <AdminPageHeader title={t("auth.change_password.title_admin")} />
        <AdminPageContent>
          <div className="mx-auto w-full max-w-[448px] pt-8">
            <ChangePasswordForm forced={false} />
          </div>
        </AdminPageContent>
      </main>
    </div>
  );
}
