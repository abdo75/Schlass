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

export function AdminLayout() {
  const { t } = useTranslation();

  return (
    <div className="flex min-h-screen bg-sidebar">
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
      <main className="flex min-w-0 flex-1 flex-col bg-background">
        <Outlet />
      </main>
    </div>
  );
}

interface AdminPageHeaderProps {
  breadcrumb?: { label: string; to: string };
  title?: string;
  subtitle?: string;
  primaryAction?: React.ReactNode;
}

export function AdminPageHeader({ breadcrumb, title, subtitle, primaryAction }: AdminPageHeaderProps) {
  return (
    <div className="flex items-center justify-between gap-6 border-b border-border bg-background px-8 py-4">
      <div className="min-w-0">
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
