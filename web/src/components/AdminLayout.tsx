import type React from "react";
import { NavLink, Link, Outlet } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { UserMenuPopover } from "@/components/UserMenuPopover";

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

function ClientsIcon() {
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
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M3 10h18" />
      <path d="M8 4v16" />
    </svg>
  );
}

function KeyIcon() {
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
      <circle cx="8" cy="15" r="4" />
      <path d="M10.85 12.15 19 4" />
      <path d="m18 5 2 2" />
      <path d="m15 8 2 2" />
    </svg>
  );
}

function CogIcon() {
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
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
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
        <NavLink
          to="/admin/clients"
          className={({ isActive }) =>
            `flex h-8 items-center gap-2.5 rounded-lg px-3 text-sm font-semibold transition-colors ${
              isActive
                ? "bg-accent text-accent-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground"
            }`
          }
        >
          <ClientsIcon />
          {t("clients.title")}
        </NavLink>
        <NavLink
          to="/admin/signing-keys"
          className={({ isActive }) =>
            `flex h-8 items-center gap-2.5 rounded-lg px-3 text-sm font-semibold transition-colors ${
              isActive
                ? "bg-accent text-accent-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground"
            }`
          }
        >
          <KeyIcon />
          {t("signing_keys.title")}
        </NavLink>
        <NavLink
          to="/admin/settings"
          className={({ isActive }) =>
            `flex h-8 items-center gap-2.5 rounded-lg px-3 text-sm font-semibold transition-colors ${
              isActive
                ? "bg-accent text-accent-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground"
            }`
          }
        >
          <CogIcon />
          {t("settings.title")}
        </NavLink>
      </nav>
    </aside>
  );
}

interface AdminLayoutProps {
  hideSidebar?: boolean;
  children?: React.ReactNode;
}

export function AdminLayout({ hideSidebar = false, children }: AdminLayoutProps) {
  return (
    <div className="flex min-h-screen bg-sidebar">
      {!hideSidebar && <AdminSidebar />}
      <main className="flex min-w-0 flex-1 flex-col bg-background">
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
      <div className="flex shrink-0 items-center gap-3">
        {primaryAction}
        {primaryAction && <div className="h-6 w-px bg-border" />}
        <UserMenuPopover />
      </div>
    </div>
  );
}

export function AdminPageContent({ children }: { children: React.ReactNode }) {
  return <div className="min-w-0 flex-1 bg-sidebar px-8 py-7">{children}</div>;
}
