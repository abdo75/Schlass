import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/features/auth/AuthContext";
import { ThemeToggle } from "@/components/ThemeToggle";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";

export function AdminLayout() {
  const { t } = useTranslation();
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    void navigate("/login", { replace: true });
  };

  const navLinkClass = (path: string) =>
    `block px-3 py-2 rounded-md text-sm transition ${
      location.pathname.startsWith(path)
        ? "bg-accent text-accent-foreground font-medium"
        : "text-muted-foreground hover:bg-muted"
    }`;

  return (
    <div className="min-h-screen flex">
      <aside className="w-56 border-r bg-card p-4 flex flex-col">
        <div className="font-bold text-lg mb-6">Schlass</div>
        <nav className="flex-1 space-y-1">
          <Link to="/admin/users" className={navLinkClass("/admin/users")}>
            {t("dashboard.nav.users")}
          </Link>
          <div className="block px-3 py-2 text-sm text-muted-foreground opacity-50">
            {t("dashboard.nav.clients")}{" "}
            <span className="text-xs">({t("dashboard.nav.soon")})</span>
          </div>
          <div className="block px-3 py-2 text-sm text-muted-foreground opacity-50">
            {t("dashboard.nav.audit")}{" "}
            <span className="text-xs">({t("dashboard.nav.soon")})</span>
          </div>
        </nav>
        <div className="border-t pt-3 space-y-2">
          <div className="px-3 text-xs text-muted-foreground">{user?.email}</div>
          <div className="px-3 text-xs text-muted-foreground opacity-70">{user?.role}</div>
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start"
            onClick={() => {
              void handleLogout();
            }}
          >
            {t("dashboard.nav.signout")}
          </Button>
          <div className="flex gap-1 px-3">
            <ThemeToggle />
            <LanguageSwitcher />
          </div>
        </div>
      </aside>
      <main className="flex-1 p-6 bg-background overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
