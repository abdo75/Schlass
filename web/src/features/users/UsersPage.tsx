import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { listUsers, type UsersListResponse } from "./api";
import type { AuthUser } from "@/features/auth/api";

const PAGE_SIZE = 25;

// Backend /api/users returns users with `status` and `created_at` in addition
// to the shared AuthUser fields. The api.ts typing uses AuthUser for historical
// parity; widen locally for table rendering.
type UserRow = AuthUser & { status?: string; created_at?: string };

export function UsersPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [data, setData] = useState<UsersListResponse | null>(null);
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    // Kick off the fetch asynchronously so the "set loading true / clear
    // error" updates happen inside a callback rather than the effect body
    // itself (react-hooks/set-state-in-effect).
    void (async () => {
      if (cancelled) return;
      setLoading(true);
      setError(null);
      try {
        const res = await listUsers(PAGE_SIZE, offset, search || undefined);
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
  }, [offset, search]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t("users.title")}</h1>
        <Button
          onClick={() => {
            void navigate("/admin/users/new");
          }}
        >
          {t("users.create_button")}
        </Button>
      </div>
      <Input
        placeholder={t("users.search_placeholder")}
        value={search}
        onChange={(e) => {
          setSearch(e.target.value);
          setOffset(0);
        }}
      />
      {loading && (
        <p className="text-sm text-muted-foreground">{t("common.loading")}</p>
      )}
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {t(`errors.${error}`)}
        </p>
      )}
      {data && (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("users.columns.email")}</TableHead>
                <TableHead>{t("users.columns.role")}</TableHead>
                <TableHead>{t("users.columns.status")}</TableHead>
                <TableHead>{t("users.columns.created_at")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data.users as UserRow[]).map((u) => (
                <TableRow
                  key={u.id}
                  onClick={() => {
                    void navigate(`/admin/users/${u.id}`);
                  }}
                  className="cursor-pointer"
                >
                  <TableCell>{u.email}</TableCell>
                  <TableCell>{t(`users.role.${u.role}`)}</TableCell>
                  <TableCell>
                    {t(`users.status.${u.status ?? "active"}`)}
                  </TableCell>
                  <TableCell>{u.created_at ?? ""}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>
              {t("users.pagination", {
                current: currentPage,
                total: totalPages,
                count: data.total,
              })}
            </span>
            <div className="space-x-2">
              <Button
                variant="outline"
                size="sm"
                disabled={offset === 0}
                onClick={() =>
                  setOffset(Math.max(0, offset - PAGE_SIZE))
                }
                aria-label={t("users.pagination_prev")}
              >
                {"\u2039"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={currentPage >= totalPages}
                onClick={() => setOffset(offset + PAGE_SIZE)}
                aria-label={t("users.pagination_next")}
              >
                {"\u203a"}
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
