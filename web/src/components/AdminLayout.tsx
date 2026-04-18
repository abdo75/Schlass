import type React from "react";
import { NavLink, Link, Outlet } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { UserMenuPopover } from "@/components/UserMenuPopover";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { ThemeToggle } from "@/components/ThemeToggle";

function UsersIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}

function ChevronLeftIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <polyline points="15 18 9 12 15 6" />
    </svg>
  );
}

export function AdminSidebar() {
  const { t } = useTranslation();
  return (
    <aside className="flex w-[220px] flex-col border-r border-border bg-sidebar px-4 py-6">
      <div className="mb-6 flex items-center gap-3 px-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-sm font-extrabold text-primary-foreground">
          S
        </div>
        <span className="text-base font-bold tracking-tight">Schlass</span>
      </div>
      <nav className="flex flex-col gap-1.5">
        <NavLink
          to="/admin/users"
          className={({ isActive }) =>
            `flex h-8 items-center gap-2.5 rounded-lg px-3 text-sm font-semibold transition-colors ${
              isActive
                ? "bg-accent text-accent-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground"
            }`
          }
        >
          <UsersIcon />
          {t("users.title")}
        </NavLink>
      </nav>
    </aside>
  );
}

interface AdminLayoutProps {
  hideSidebar?: boolean;
  children?: React.ReactNode;
}

function AdminTopBar({ showBrand }: { showBrand: boolean }) {
  return (
    <div className="flex h-[52px] shrink-0 items-center justify-between border-b border-border bg-background px-6">
      <div>
        {showBrand && (
          <Link to="/" className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-sm font-extrabold text-primary-foreground">
              S
            </div>
            <span className="text-base font-bold tracking-tight">Schlass</span>
          </Link>
        )}
      </div>
      <div className="flex items-center gap-2">
        <LanguageSwitcher />
        <ThemeToggle />
        <UserMenuPopover />
      </div>
    </div>
  );
}

export function AdminLayout({ hideSidebar = false, children }: AdminLayoutProps) {
  return (
    <div className="flex min-h-screen bg-sidebar">
      {!hideSidebar && <AdminSidebar />}
      <main className="flex min-w-0 flex-1 flex-col bg-background">
        <AdminTopBar showBrand={hideSidebar} />
        {children ?? <Outlet />}
      </main>
    </div>
  );
}

interface AdminPageHeaderProps {
  breadcrumb?: { label: string; to: string };
  breadcrumbPath?: Array<{ label: string; to?: string }>;
  title?: string;
  subtitle?: string;
  primaryAction?: React.ReactNode;
}

export function AdminPageHeader({
  breadcrumb,
  breadcrumbPath,
  title,
  subtitle,
  primaryAction,
}: AdminPageHeaderProps) {
  return (
    <div className="flex items-center justify-between gap-6 border-b border-border bg-background px-8 py-4">
      <div className="min-w-0">
        {breadcrumbPath && breadcrumbPath.length > 0 ? (
          <nav
            aria-label="Breadcrumb"
            className="flex items-center gap-2 text-lg font-semibold leading-tight tracking-tight"
          >
            {breadcrumbPath.map((seg, i) => {
              const isLast = i === breadcrumbPath.length - 1;
              return (
                <span key={`${seg.label}-${i}`} className="flex items-center gap-2 min-w-0">
                  {i > 0 && (
                    <span
                      className="text-muted-foreground/60 text-base select-none"
                      aria-hidden="true"
                    >
                      /
                    </span>
                  )}
                  {isLast || !seg.to ? (
                    <span className="truncate text-foreground">{seg.label}</span>
                  ) : (
                    <Link
                      to={seg.to}
                      className="truncate text-muted-foreground hover:text-foreground"
                    >
                      {seg.label}
                    </Link>
                  )}
                </span>
              );
            })}
          </nav>
        ) : (
          <>
            {breadcrumb && (
              <Link
                to={breadcrumb.to}
                className="inline-flex items-center gap-1 text-[13px] leading-none text-muted-foreground hover:text-foreground"
              >
                <ChevronLeftIcon />
                {breadcrumb.label}
              </Link>
            )}
            {title && (
              <div className="mt-0.5 text-lg font-semibold leading-tight tracking-tight">{title}</div>
            )}
            {subtitle && (
              <div className="mt-0.5 text-[13px] leading-snug text-muted-foreground">{subtitle}</div>
            )}
          </>
        )}
      </div>
      {primaryAction && <div className="shrink-0">{primaryAction}</div>}
    </div>
  );
}

export function AdminPageContent({ children }: { children: React.ReactNode }) {
  return <div className="min-w-0 flex-1 bg-sidebar px-8 py-7">{children}</div>;
}
