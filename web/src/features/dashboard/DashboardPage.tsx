import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/features/auth/AuthContext";

export function DashboardPage() {
  const { t } = useTranslation();
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <Card className="max-w-md w-full">
        <CardHeader>
          <CardTitle>{t("dashboard.title")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p>{t("dashboard.welcome", { email: user?.email })}</p>
          <Button onClick={handleLogout}>{t("auth.logout")}</Button>
        </CardContent>
      </Card>
    </div>
  );
}
