/* eslint-disable react-refresh/only-export-components */
import { useTranslation } from "react-i18next";

export type PageEntry = number | "...";

export function buildPageList(currentPage: number, totalPages: number): PageEntry[] {
  if (totalPages <= 5) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }
  if (currentPage <= 3) {
    return [1, 2, 3, "...", totalPages];
  }
  if (currentPage >= totalPages - 2) {
    return [1, "...", totalPages - 2, totalPages - 1, totalPages];
  }
  return [1, "...", currentPage - 1, currentPage, currentPage + 1, "...", totalPages];
}

interface PaginationProps {
  currentPage: number;
  totalPages: number;
  totalCount: number;
  pageSize: number;
  onPageChange: (page: number) => void;
}

export function Pagination({
  currentPage,
  totalPages,
  totalCount,
  pageSize,
  onPageChange,
}: PaginationProps) {
  const { t } = useTranslation();
  const from = totalCount === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const to = Math.min(currentPage * pageSize, totalCount);
  const entries = buildPageList(currentPage, totalPages);

  return (
    <div className="flex items-center justify-between text-[13px] text-muted-foreground">
      <div>
        {t("users.pagination.showing", { from, to, total: totalCount })}
      </div>
      <div className="flex items-center gap-1">
        <button
          type="button"
          disabled={currentPage === 1}
          onClick={() => onPageChange(currentPage - 1)}
          style={{ fontFamily: "inherit" }}
          className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-background px-3 text-sm text-foreground disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
            <polyline points="15 18 9 12 15 6" />
          </svg>
          {t("users.pagination.prev")}
        </button>
        <div className="w-2" />
        {entries.map((entry, i) =>
          entry === "..." ? (
            <span
              key={`ellipsis-${i}`}
              className="inline-flex h-8 min-w-8 items-center justify-center text-sm font-semibold text-muted-foreground"
            >
              …
            </span>
          ) : (
            <button
              key={entry}
              type="button"
              aria-current={entry === currentPage ? "page" : undefined}
              onClick={() => onPageChange(entry)}
              style={{ fontFamily: "inherit" }}
              className={`inline-flex h-8 min-w-8 items-center justify-center rounded-lg px-2.5 text-sm ${
                entry === currentPage
                  ? "bg-primary text-primary-foreground font-semibold"
                  : "text-foreground hover:bg-muted"
              }`}
            >
              {entry}
            </button>
          ),
        )}
        <div className="w-2" />
        <button
          type="button"
          disabled={currentPage === totalPages}
          onClick={() => onPageChange(currentPage + 1)}
          style={{ fontFamily: "inherit" }}
          className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-background px-3 text-sm text-foreground disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {t("users.pagination.next")}
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </button>
      </div>
    </div>
  );
}
