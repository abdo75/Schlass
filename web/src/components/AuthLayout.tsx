import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useAuth } from "@/features/auth/AuthContext";

interface AuthLayoutProps {
  children: ReactNode;
  forceChangeMode?: boolean;
}

export function AuthLayout({ children, forceChangeMode = false }: AuthLayoutProps) {
  const { t } = useTranslation();
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleSignOut = async () => {
    await logout();
    void navigate("/login", { replace: true });
  };

  return (
    <div className="relative min-h-screen bg-sidebar">
      {/* Top-right chrome */}
      <div className="absolute right-6 top-5 flex items-center gap-2">
        <LanguageSwitcher />
        <ThemeToggle />
        {forceChangeMode && (
          <button
            type="button"
            onClick={() => void handleSignOut()}
            aria-label={t("user_menu.sign_out")}
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-background text-muted-foreground hover:text-foreground"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
          </button>
        )}
      </div>

      {/* Brand lockup */}
      <div className="absolute left-1/2 top-12 flex -translate-x-1/2 items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-[10px] bg-primary text-lg font-extrabold text-primary-foreground">
          S
        </div>
        <div>
          <div className="text-lg font-bold leading-tight tracking-tight">Schlass</div>
          <div className="mt-0.5 text-xs leading-tight text-muted-foreground">
            {t("common.tagline")}
          </div>
        </div>
      </div>

      {/* Card container */}
      <div className="mx-auto flex min-h-screen max-w-[448px] flex-col px-6 pt-36 pb-12">
        {children}
      </div>
    </div>
  );
}
