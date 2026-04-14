import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { LanguageSwitcher } from "./LanguageSwitcher";

interface AuthLayoutProps {
  children: ReactNode;
}

export function AuthLayout({ children }: AuthLayoutProps) {
  const { t } = useTranslation();

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center bg-background p-4">
      <LanguageSwitcher />
      <div className="mb-8 text-center">
        <h1 className="text-3xl font-bold tracking-tight text-primary">
          {t("common.appName")}
        </h1>
        <p className="text-sm text-muted-foreground">{t("common.tagline")}</p>
      </div>
      {children}
    </div>
  );
}
