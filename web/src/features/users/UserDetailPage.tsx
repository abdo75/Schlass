import { useState, useEffect, useCallback, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, useParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  getUser,
  updateUser,
  disableUser,
  enableUser,
  deleteUser,
  resetUserPassword,
  terminateSession,
  terminateAllSessions,
  type UserDetailResponse,
} from "./api";
import type { AuthUser } from "@/features/auth/api";

type Role = "super_admin" | "user";

// The list/detail endpoints augment AuthUser with status + created_at, but
// api.ts intentionally keeps the shared AuthUser type narrow. Widen locally
// for rendering.
type UserRow = AuthUser & { status?: string; created_at?: string };

function extractErrorCode(err: unknown): string {
  return err && typeof err === "object" && "code" in err
    ? String((err as { code: unknown }).code)
    : "INTERNAL_ERROR";
}

export function UserDetailPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { id = "" } = useParams<{ id: string }>();

  const [data, setData] = useState<UserDetailResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorCode, setErrorCode] = useState<string | null>(null);

  // Edit mode state
  const [editing, setEditing] = useState(false);
  const [editEmail, setEditEmail] = useState("");
  const [editRole, setEditRole] = useState<Role>("user");
  const [saving, setSaving] = useState(false);

  // Reset password inline form state
  const [resetOpen, setResetOpen] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [resetSubmitting, setResetSubmitting] = useState(false);
  const [resetSuccess, setResetSuccess] = useState(false);

  // AlertDialog state for destructive actions (use controlled to simplify tests)
  const [disableDialogOpen, setDisableDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [killAllDialogOpen, setKillAllDialogOpen] = useState(false);

  const refetch = useCallback(async () => {
    setLoading(true);
    setErrorCode(null);
    try {
      const res = await getUser(id);
      setData(res);
      return res;
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
      return null;
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void refetch();
  }, [refetch]);

  const user = (data?.user ?? null) as UserRow | null;

  const startEdit = () => {
    if (!user) return;
    setEditEmail(user.email);
    setEditRole((user.role as Role) ?? "user");
    setEditing(true);
    setErrorCode(null);
  };

  const cancelEdit = () => {
    setEditing(false);
    setErrorCode(null);
  };

  const handleSave = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setErrorCode(null);
    try {
      await updateUser(id, { email: editEmail, role: editRole });
      await refetch();
      setEditing(false);
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    } finally {
      setSaving(false);
    }
  };

  const handleResetPassword = async (e: FormEvent) => {
    e.preventDefault();
    setResetSubmitting(true);
    setErrorCode(null);
    setResetSuccess(false);
    try {
      await resetUserPassword(id, newPassword);
      await refetch();
      setNewPassword("");
      setResetOpen(false);
      setResetSuccess(true);
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    } finally {
      setResetSubmitting(false);
    }
  };

  const handleDisable = async () => {
    setErrorCode(null);
    try {
      await disableUser(id);
      await refetch();
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    } finally {
      setDisableDialogOpen(false);
    }
  };

  const handleEnable = async () => {
    setErrorCode(null);
    try {
      await enableUser(id);
      await refetch();
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    }
  };

  const handleDelete = async () => {
    setErrorCode(null);
    try {
      await deleteUser(id);
      setDeleteDialogOpen(false);
      void navigate("/admin/users");
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
      setDeleteDialogOpen(false);
    }
  };

  const handleKillSession = async (token: string) => {
    setErrorCode(null);
    try {
      await terminateSession(id, token);
      await refetch();
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    }
  };

  const handleKillAllSessions = async () => {
    setErrorCode(null);
    try {
      await terminateAllSessions(id);
      await refetch();
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    } finally {
      setKillAllDialogOpen(false);
    }
  };

  if (loading && !data) {
    return (
      <p className="text-sm text-muted-foreground">{t("users.detail.loading")}</p>
    );
  }

  if (!user) {
    return (
      <div className="space-y-4">
        {errorCode && (
          <p className="text-destructive text-sm" role="alert">
            {t(`errors.${errorCode}`)}
          </p>
        )}
        <Button
          variant="outline"
          onClick={() => {
            void navigate("/admin/users");
          }}
        >
          {t("users.detail.back")}
        </Button>
      </div>
    );
  }

  const status = user.status ?? "active";
  const isActive = status === "active";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <button
            type="button"
            className="text-sm text-muted-foreground underline-offset-2 hover:underline"
            onClick={() => {
              void navigate("/admin/users");
            }}
          >
            {"\u2039 "}
            {t("users.detail.back")}
          </button>
          <h1 className="text-2xl font-bold">{user.email}</h1>
        </div>
        {!editing && (
          <Button variant="outline" onClick={startEdit}>
            {t("users.detail.edit")}
          </Button>
        )}
      </div>

      {errorCode && (
        <p className="text-destructive text-sm" role="alert">
          {t(`errors.${errorCode}`)}
        </p>
      )}
      {resetSuccess && (
        <p className="text-sm text-muted-foreground" role="status">
          {t("users.detail.reset_password_success")}
        </p>
      )}

      {/* View / Edit section */}
      {!editing ? (
        <dl className="grid gap-3 rounded-md border p-4 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted-foreground">
              {t("users.detail.email_label")}
            </dt>
            <dd className="font-medium">{user.email}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">
              {t("users.detail.role_label")}
            </dt>
            <dd className="font-medium">{t(`users.role.${user.role}`)}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">
              {t("users.detail.status_label")}
            </dt>
            <dd className="font-medium">{t(`users.status.${status}`)}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">
              {t("users.detail.created_at_label")}
            </dt>
            <dd className="font-medium">{user.created_at ?? ""}</dd>
          </div>
          {user.force_password_change && (
            <div className="sm:col-span-2">
              <dd className="text-sm text-amber-600">
                {t("users.detail.force_password_change")}
              </dd>
            </div>
          )}
        </dl>
      ) : (
        <form
          onSubmit={(e) => {
            void handleSave(e);
          }}
          className="grid gap-4 rounded-md border p-4 sm:grid-cols-2"
        >
          <div className="space-y-2">
            <Label htmlFor="edit-email">{t("users.detail.email_label")}</Label>
            <Input
              id="edit-email"
              type="email"
              required
              value={editEmail}
              onChange={(e) => setEditEmail(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="edit-role">{t("users.detail.role_label")}</Label>
            <select
              id="edit-role"
              value={editRole}
              onChange={(e) => setEditRole(e.target.value as Role)}
              className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
            >
              <option value="user">{t("users.role.user")}</option>
              <option value="super_admin">{t("users.role.super_admin")}</option>
            </select>
          </div>
          <div className="sm:col-span-2 flex items-center gap-2">
            <Button type="submit" disabled={saving}>
              {saving ? t("users.detail.saving") : t("users.detail.save")}
            </Button>
            <Button type="button" variant="outline" onClick={cancelEdit}>
              {t("users.detail.cancel")}
            </Button>
          </div>
        </form>
      )}

      {/* Actions panel */}
      <section className="space-y-3 rounded-md border p-4">
        <h2 className="text-lg font-semibold">
          {t("users.detail.actions_heading")}
        </h2>

        {/* Reset password */}
        {!resetOpen ? (
          <Button
            variant="outline"
            onClick={() => {
              setResetOpen(true);
              setResetSuccess(false);
            }}
          >
            {t("users.detail.reset_password")}
          </Button>
        ) : (
          <form
            onSubmit={(e) => {
              void handleResetPassword(e);
            }}
            className="flex flex-col gap-2 sm:flex-row sm:items-end"
          >
            <div className="flex-1 space-y-2">
              <Label htmlFor="new-password">
                {t("users.detail.new_password_label")}
              </Label>
              <Input
                id="new-password"
                type="password"
                autoComplete="new-password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div className="flex gap-2">
              <Button type="submit" disabled={resetSubmitting}>
                {t("users.detail.reset_password_submit")}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setResetOpen(false);
                  setNewPassword("");
                }}
              >
                {t("users.detail.cancel")}
              </Button>
            </div>
          </form>
        )}

        <div className="flex flex-wrap gap-2 pt-2">
          {isActive ? (
            <Button
              variant="outline"
              onClick={() => setDisableDialogOpen(true)}
            >
              {t("users.detail.disable")}
            </Button>
          ) : (
            <Button
              variant="outline"
              onClick={() => {
                void handleEnable();
              }}
            >
              {t("users.detail.enable")}
            </Button>
          )}
          <Button
            variant="destructive"
            onClick={() => setDeleteDialogOpen(true)}
          >
            {t("users.detail.delete")}
          </Button>
        </div>
      </section>

      {/* Sessions section */}
      <section className="space-y-3 rounded-md border p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">
            {t("users.detail.sessions_heading")}
          </h2>
          {data && data.sessions.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setKillAllDialogOpen(true)}
            >
              {t("users.detail.kill_all_sessions")}
            </Button>
          )}
        </div>
        {data && data.sessions.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t("users.detail.no_sessions")}
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>
                  {t("users.detail.sessions_columns.ip")}
                </TableHead>
                <TableHead>
                  {t("users.detail.sessions_columns.user_agent")}
                </TableHead>
                <TableHead>
                  {t("users.detail.sessions_columns.created_at")}
                </TableHead>
                <TableHead>
                  {t("users.detail.sessions_columns.last_seen_at")}
                </TableHead>
                <TableHead>
                  {t("users.detail.sessions_columns.actions")}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data?.sessions.map((session) => (
                <TableRow key={session.token}>
                  <TableCell>{session.ip_address}</TableCell>
                  <TableCell
                    className="max-w-xs truncate"
                    title={session.user_agent}
                  >
                    {session.user_agent}
                  </TableCell>
                  <TableCell>{session.created_at}</TableCell>
                  <TableCell>{session.last_seen_at}</TableCell>
                  <TableCell>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        void handleKillSession(session.token);
                      }}
                    >
                      {t("users.detail.kill_session")}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </section>

      {/* Disable confirm */}
      <AlertDialog
        open={disableDialogOpen}
        onOpenChange={setDisableDialogOpen}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("users.confirm.disable_title")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("users.confirm.disable_body")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("users.confirm.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                void handleDisable();
              }}
            >
              {t("users.confirm.disable_confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Delete confirm */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("users.confirm.delete_title")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("users.confirm.delete_body")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("users.confirm.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                void handleDelete();
              }}
            >
              {t("users.confirm.delete_confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Kill all sessions confirm */}
      <AlertDialog
        open={killAllDialogOpen}
        onOpenChange={setKillAllDialogOpen}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("users.confirm.kill_all_sessions_title")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("users.confirm.kill_all_sessions_body")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("users.confirm.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                void handleKillAllSessions();
              }}
            >
              {t("users.confirm.kill_all_sessions_confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
