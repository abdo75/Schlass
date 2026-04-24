import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { buttonVariants } from "@/components/ui/button";
import { StatusBadge } from "@/components/StatusBadge";
import { RoleBadge } from "@/components/RoleBadge";
import { Pagination } from "@/components/Pagination";
import { UsersTableSkeleton } from "@/components/PageSkeleton";
import { useAuth } from "@/features/auth/AuthContext";
import { listUsers, type UsersListResponse, type UserRow } from "./api";

const PAGE_SIZE = 10;

function PlusIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <line x1="12" y1="5" x2="12" y2="19" />
      <line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  );
}

function MagnifierIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="text-muted-foreground"
    >
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

function relativeTime(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(diffMs / 60000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function UserAvatar({ user }: { user: UserRow }) {
  const isAdmin = user.role === "super_admin";
  const isDisabled = user.status === "disabled";
  const initial = user.email[0]?.toUpperCase() ?? "?";

  return (
    <div
      className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-sm font-semibold ${
        isAdmin
          ? "bg-primary text-primary-foreground"
          : "border border-border bg-muted text-foreground"
      } ${isDisabled ? "opacity-60" : ""}`}
    >
      {initial}
    </div>
  );
}

export function UsersPage() {
  const { t } = useTranslation();
  const { user: currentUser } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [data, setData] = useState<UsersListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const pageParam = parseInt(searchParams.get("page") ?? "1", 10);
  const currentPage = isNaN(pageParam) || pageParam < 1 ? 1 : pageParam;
  const searchQuery = searchParams.get("q") ?? "";

  const offset = (currentPage - 1) * PAGE_SIZE;

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (cancelled) return;
      setLoading(true);
      setError(null);
      try {
        const res = await listUsers(PAGE_SIZE, offset, searchQuery || undefined);
        if (!cancelled) setData(res);
      } catch (err: unknown) {
        if (cancelled) return;
        const code =
          err && typeof err === "object" && "code" in err
            ? String((err as { code: unknown }).code)
            : "INTERNAL_ERROR";
        setError(code);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [offset, searchQuery]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const adminCount = data
    ? data.users.filter((u) => u.role === "super_admin").length
    : 0;

  const subtitle = data
    ? `${data.total} users · ${adminCount} administrator${adminCount !== 1 ? "s" : ""}`
    : undefined;

  function handlePageChange(page: number) {
    const params = new URLSearchParams(searchParams);
    params.set("page", String(page));
    setSearchParams(params);
  }

  function handleSearchChange(value: string) {
    const params = new URLSearchParams(searchParams);
    if (value) {
      params.set("q", value);
    } else {
      params.delete("q");
    }
    params.set("page", "1");
    setSearchParams(params);
  }

  return (
    <>
      <AdminPageHeader
        title={t("users.title")}
        subtitle={subtitle}
        primaryAction={
          <Link
            to="/admin/users/new"
            className={buttonVariants({ size: "default" }) + " flex items-center gap-1.5"}
          >
            <PlusIcon />
            {t("users.create_button")}
          </Link>
        }
      />
      <AdminPageContent>
        {loading && !data ? (
          <UsersTableSkeleton />
        ) : (
          <div className="space-y-4">
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {t(`errors.${error}`)}
              </p>
            )}
            {/* Search toolbar */}
            <div className="relative h-8 max-w-[400px]">
              <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2">
                <MagnifierIcon />
              </span>
              <input
                type="text"
                placeholder={t("users.search_placeholder")}
                value={searchQuery}
                onChange={(e) => handleSearchChange(e.target.value)}
                className="h-8 w-full rounded-lg border border-border bg-background pl-8 pr-3 text-sm outline-none focus:ring-2 focus:ring-primary/40"
              />
            </div>

            {/* Table */}
            <div className="overflow-hidden rounded-xl border border-border bg-background">
              {/* Header */}
              <div className="grid grid-cols-[1fr_120px_120px_140px_40px] gap-3 border-b border-border bg-sidebar px-6 py-3">
                <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
                  {t("users.columns.email")}
                </span>
                <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
                  {t("users.columns.role")}
                </span>
                <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
                  {t("users.columns.status")}
                </span>
                <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
                  {t("users.columns.created_at")}
                </span>
                <span />
              </div>

              {/* Rows */}
              {data && data.users.length === 0 ? (
                <div className="px-6 py-8 text-center text-sm text-muted-foreground">
                  No users found.
                </div>
              ) : (
                data?.users.map((u) => {
                  const isSelf = currentUser?.id === u.id;
                  const isDisabled = u.status === "disabled";
                  return (
                    <Link
                      key={u.id}
                      to={`/admin/users/${u.id}`}
                      className={`grid grid-cols-[1fr_120px_120px_140px_40px] items-center gap-3 border-b border-border px-6 py-4 last:border-b-0 hover:bg-muted/50 ${
                        isSelf ? "bg-accent/40" : ""
                      }`}
                    >
                      {/* Email + avatar */}
                      <div className="flex min-w-0 items-center gap-3">
                        <UserAvatar user={u} />
                        <div className="min-w-0">
                          <div
                            className={`truncate text-sm font-medium ${
                              isDisabled
                                ? "text-muted-foreground opacity-60"
                                : "text-foreground"
                            }`}
                          >
                            {u.email}
                          </div>
                          {isSelf && (
                            <div className="text-[12px] text-muted-foreground">
                              {t("users.list.you")}
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Role */}
                      <div>
                        <RoleBadge role={u.role as "super_admin" | "user"} />
                      </div>

                      {/* Status */}
                      <div>
                        <StatusBadge status={u.status} />
                      </div>

                      {/* Created */}
                      <div className="text-sm text-muted-foreground">
                        {relativeTime(u.created_at)}
                      </div>

                      {/* Chevron */}
                      <div className="text-right text-lg text-muted-foreground">
                        {"\u203a"}
                      </div>
                    </Link>
                  );
                })
              )}
            </div>

            {/* Pagination */}
            {data && data.total > PAGE_SIZE && (
              <Pagination
                currentPage={currentPage}
                totalPages={totalPages}
                totalCount={data.total}
                pageSize={PAGE_SIZE}
                onPageChange={handlePageChange}
              />
            )}
          </div>
        )}
      </AdminPageContent>
    </>
  );
}
