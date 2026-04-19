import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { buttonVariants } from "@/components/ui/button";
import { StatusBadge } from "@/components/ui/status-badge";
import { listClients, type ClientDTO } from "./api";

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

function ClientAvatar({ client }: { client: ClientDTO }) {
  const initial = (client.name[0] ?? "?").toUpperCase();
  const isDisabled = client.status === "disabled";
  return (
    <div
      className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground ${
        isDisabled ? "opacity-60" : ""
      }`}
    >
      {initial}
    </div>
  );
}

type Filter = "active" | "disabled" | "all";

export function ClientsPage() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const rawStatus = searchParams.get("status");
  const filter: Filter =
    rawStatus === "disabled" || rawStatus === "all" ? rawStatus : "active";

  const [clients, setClients] = useState<ClientDTO[] | null>(null);
  const [counts, setCounts] = useState<{ active: number; disabled: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch the view data + the subtitle counts in parallel.
  useEffect(() => {
    let cancel = false;
    setLoading(true);
    setError(null);

    const viewPromise = listClients(filter);
    const allPromise = filter === "all" ? null : listClients("all");

    Promise.all([viewPromise, allPromise])
      .then(([view, all]) => {
        if (cancel) return;
        setClients(view.clients);
        const source = all ? all.clients : view.clients;
        setCounts({
          active: source.filter((c) => c.status === "active").length,
          disabled: source.filter((c) => c.status === "disabled").length,
        });
      })
      .catch((err: { code?: string }) => {
        if (cancel) return;
        setError(err.code ?? "INTERNAL_ERROR");
      })
      .finally(() => {
        if (!cancel) setLoading(false);
      });
    return () => {
      cancel = true;
    };
  }, [filter]);

  function setFilter(next: Filter) {
    const params = new URLSearchParams(searchParams);
    if (next === "active") {
      params.delete("status");
    } else {
      params.set("status", next);
    }
    setSearchParams(params);
  }

  const subtitle = counts
    ? `${counts.active} active · ${counts.disabled} disabled`
    : undefined;

  return (
    <>
      <AdminPageHeader
        title={t("clients.title")}
        subtitle={subtitle}
        primaryAction={
          <Link
            to="/admin/clients/new"
            className={buttonVariants({ size: "default" }) + " flex items-center gap-1.5"}
          >
            <PlusIcon />
            {t("clients.create_button")}
          </Link>
        }
      />
      <AdminPageContent>
        <div className="space-y-4">
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {t(`errors.${error}`, { defaultValue: error })}
            </p>
          )}

          {/* Filter pills — no borders above or below */}
          <div className="inline-flex h-8 overflow-hidden rounded-lg border border-border bg-background text-sm">
            {(["active", "disabled", "all"] as const).map((f, i) => {
              const isActive = filter === f;
              return (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`h-8 px-3.5 capitalize transition-colors ${
                    isActive
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  } ${i !== 0 ? "border-l border-border" : ""}`}
                  aria-pressed={isActive}
                >
                  {t(`clients.filter.${f}`, {
                    defaultValue: f.charAt(0).toUpperCase() + f.slice(1),
                  })}
                </button>
              );
            })}
          </div>

          {/* Table */}
          <div className="overflow-hidden rounded-xl border border-border bg-background">
            <div className="grid grid-cols-[1fr_120px_140px_40px] gap-3 border-b border-border bg-sidebar px-6 py-3">
              <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
                {t("clients.columns.name", { defaultValue: "Name" })}
              </span>
              <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
                {t("clients.columns.status", { defaultValue: "Status" })}
              </span>
              <span className="text-[12px] font-semibold uppercase tracking-wide text-muted-foreground">
                {t("clients.columns.created", { defaultValue: "Created" })}
              </span>
              <span />
            </div>

            {loading && !clients ? (
              <div className="px-6 py-8 text-center text-sm text-muted-foreground">
                Loading…
              </div>
            ) : clients && clients.length === 0 ? (
              <div className="px-6 py-8 text-center text-sm text-muted-foreground">
                No clients found.
              </div>
            ) : (
              clients?.map((c) => {
                const isDisabled = c.status === "disabled";
                return (
                  <Link
                    key={c.id}
                    to={`/admin/clients/${c.id}`}
                    className="grid grid-cols-[1fr_120px_140px_40px] items-center gap-3 border-b border-border px-6 py-4 last:border-b-0 hover:bg-muted/50"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <ClientAvatar client={c} />
                      <div
                        className={`truncate text-sm font-medium ${
                          isDisabled
                            ? "text-muted-foreground opacity-60"
                            : "text-foreground"
                        }`}
                      >
                        {c.name}
                      </div>
                    </div>
                    <div>
                      <StatusBadge status={c.status} />
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {relativeTime(c.created_at)}
                    </div>
                    <div className="text-right text-lg text-muted-foreground">
                      {"\u203a"}
                    </div>
                  </Link>
                );
              })
            )}
          </div>
        </div>
      </AdminPageContent>
    </>
  );
}
