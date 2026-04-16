import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/features/auth/AuthContext";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { useTheme, type Theme } from "@/components/ThemeToggle";

function SunIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="5" />
      <line x1="12" y1="1" x2="12" y2="3" />
      <line x1="12" y1="21" x2="12" y2="23" />
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
      <line x1="1" y1="12" x2="3" y2="12" />
      <line x1="21" y1="12" x2="23" y2="12" />
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

function MonitorIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      style={{ transition: "transform 150ms", transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

export function UserMenuPopover() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { theme, setTheme } = useTheme();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const handlePointerDown = (e: PointerEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    document.addEventListener("pointerdown", handlePointerDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("pointerdown", handlePointerDown);
    };
  }, [open]);

  const email = user?.email ?? "";
  const role = user?.role ?? "";
  const avatarLetter = email.charAt(0).toUpperCase();

  const handleChangePassword = () => {
    setOpen(false);
    void navigate("/change-password");
  };

  const handleSignOut = async () => {
    setOpen(false);
    await logout();
    void navigate("/login", { replace: true });
  };

  const themeOptions: { value: Theme; label: string; icon: React.ReactNode }[] = [
    { value: "light", label: t("user_menu.theme.light"), icon: <SunIcon /> },
    { value: "dark", label: t("user_menu.theme.dark"), icon: <MoonIcon /> },
    { value: "system", label: t("user_menu.theme.system"), icon: <MonitorIcon /> },
  ];

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        aria-label={email}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className={`inline-flex h-8 items-center gap-2 rounded-[20px] border pl-[4px] pr-3 text-sm transition-all ${
          open
            ? "border-primary ring-2 ring-primary/20"
            : "border-border hover:border-border/80"
        }`}
      >
        <span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary text-[11px] font-bold text-primary-foreground">
          {avatarLetter}
        </span>
        <span className="max-w-[140px] truncate">{email}</span>
        <ChevronIcon open={open} />
      </button>

      {open && (
        <div className="absolute right-0 top-[calc(100%+6px)] z-50 w-[280px] rounded-xl border border-border bg-background shadow-2xl">
          <div className="border-b border-border bg-sidebar p-4">
            <div className="flex items-center gap-3">
              <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">
                {avatarLetter}
              </span>
              <div className="min-w-0">
                <p className="truncate text-[14px] font-medium">{email}</p>
                <p className="text-[12px] text-accent-foreground">{role}</p>
              </div>
            </div>
          </div>

          <div className="border-b border-border p-4">
            <p className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-muted-foreground">
              {t("user_menu.theme.heading")}
            </p>
            <div className="grid grid-cols-3 gap-1">
              {themeOptions.map(({ value, label, icon }) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setTheme(value)}
                  className={`inline-flex h-8 flex-col items-center justify-center gap-0.5 rounded-md border text-[11px] transition-colors ${
                    theme === value
                      ? "border-primary bg-accent text-accent-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {icon}
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="border-b border-border p-4">
            <p className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-muted-foreground">
              {t("user_menu.language.heading")}
            </p>
            <LanguageSwitcher />
          </div>

          <div className="p-1.5">
            <button
              type="button"
              onClick={handleChangePassword}
              className="flex h-9 w-full items-center rounded-md px-3 text-sm transition-colors hover:bg-accent"
            >
              {t("user_menu.change_password")}
            </button>
            <button
              type="button"
              onClick={() => void handleSignOut()}
              className="flex h-9 w-full items-center rounded-md px-3 text-sm font-medium text-destructive transition-colors hover:bg-accent"
            >
              {t("user_menu.sign_out")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
