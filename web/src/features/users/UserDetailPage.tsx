import { useState, useEffect, useRef, useCallback, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate, useParams, Link } from "react-router-dom";
import {
  Lock,
  Ban,
  Check,
  Trash2,
  UserX,
  Laptop,
  Smartphone,
  ChevronDown,
} from "lucide-react";
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
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { TempPasswordModal } from "@/components/TempPasswordModal";
import { StatusBadge } from "@/components/ui/status-badge";
import { RoleBadge, type UserRole } from "@/components/ui/role-badge";
import { useAuth } from "@/features/auth/AuthContext";
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
  type UserSession,
} from "./api";

type Role = "super_admin" | "user";

function extractErrorCode(err: unknown): string {
  return err && typeof err === "object" && "code" in err
    ? String((err as { code: unknown }).code)
    : "INTERNAL_ERROR";
}

/** Simple device detection from user_agent string. */
function parseDevice(ua: string): { icon: "phone" | "laptop"; label: string } {
  const isPhone =
    /iPhone|Android|Mobile/i.test(ua);
  let browser = "Unknown";
  if (/Firefox/i.test(ua)) browser = "Firefox";
  else if (/Edg/i.test(ua)) browser = "Edge";
  else if (/Chrome/i.test(ua)) browser = "Chrome";
  else if (/Safari/i.test(ua)) browser = "Safari";

  let os = "";
  if (/iPhone|iPad/i.test(ua)) os = "iPhone";
  else if (/Android/i.test(ua)) os = "Android";
  else if (/Mac OS/i.test(ua)) os = "macOS";
  else if (/Windows/i.test(ua)) os = "Windows";
  else if (/Linux/i.test(ua)) os = "Linux";

  const label = os ? `${browser} on ${os}` : browser;
  return { icon: isPhone ? "phone" : "laptop", label };
}

function formatRelativeTime(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function UserDetailPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { id = "" } = useParams<{ id: string }>();
  const { user: me } = useAuth();

  const [data, setData] = useState<UserDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [errorCode, setErrorCode] = useState<string | null>(null);

  // Edit mode state
  const [editing, setEditing] = useState(false);
  const [editEmail, setEditEmail] = useState("");
  const [editRole, setEditRole] = useState<Role>("user");
  const [roleOpen, setRoleOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  // Confirm dialog state
  const [disableOpen, setDisableOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);
  const [terminateAllOpen, setTerminateAllOpen] = useState(false);
  const [terminateSingleOpen, setTerminateSingleOpen] = useState<{
    token: string;
    label: string;
  } | null>(null);

  // Reset password flow
  const [tempPassword, setTempPassword] = useState<string | null>(null);

  const refetch = useCallback(async () => {
    setLoading(true);
    setErrorCode(null);
    setNotFound(false);
    try {
      const res = await getUser(id);
      setData(res);
    } catch (err: unknown) {
      const code = extractErrorCode(err);
      if (code === "USER_NOT_FOUND") {
        setNotFound(true);
      } else {
        setErrorCode(code);
      }
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void refetch();
  }, [refetch]);

  const user = data?.user ?? null;
  const sessions = data?.sessions ?? [];
  const isSelf = user?.id === me?.id;
  const isActive = user?.status === "active";

  // Edit handlers
  const startEdit = () => {
    if (!user) return;
    setEditEmail(user.email);
    setEditRole((user.role as Role) ?? "user");
    setEditing(true);
    setEditError(null);
    setErrorCode(null);
  };

  const cancelEdit = () => {
    setEditing(false);
    setEditError(null);
  };

  const handleSave = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setEditError(null);
    try {
      await updateUser(id, { email: editEmail, role: editRole });
      await refetch();
      setEditing(false);
    } catch (err: unknown) {
      setEditError(extractErrorCode(err));
    } finally {
      setSaving(false);
    }
  };

  // Action handlers
  const handleResetPassword = async () => {
    setErrorCode(null);
    try {
      const res = await resetUserPassword(id);
      setTempPassword(res.temporary_password);
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    }
  };

  const handleDisable = async () => {
    setErrorCode(null);
    try {
      await disableUser(id);
      await refetch();
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
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
      void navigate("/admin/users");
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    }
  };

  const handleTerminateSession = async (token: string) => {
    setErrorCode(null);
    try {
      await terminateSession(id, token);
      await refetch();
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    }
  };

  const handleTerminateAll = async () => {
    setErrorCode(null);
    try {
      await terminateAllSessions(id);
      await refetch();
    } catch (err: unknown) {
      setErrorCode(extractErrorCode(err));
    }
  };

  // --- Not-found fallback ---
  if (notFound) {
    return (
      <>
        <AdminPageHeader
          breadcrumb={{ label: t("users.title"), to: "/admin/users" }}
        />
        <AdminPageContent>
          <div className="flex justify-center pt-16">
            <Card className="w-full max-w-md text-center">
              <CardContent className="flex flex-col items-center gap-4 py-10 px-6">
                <div className="flex size-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
                  <UserX className="size-7" />
                </div>
                <p className="text-base font-semibold">User not found</p>
                <p className="text-[13px] text-muted-foreground">
                  They may have been deleted by another administrator, or the
                  link is incorrect.
                </p>
                <Link to="/admin/users">
                  <Button>Back to users</Button>
                </Link>
              </CardContent>
            </Card>
          </div>
        </AdminPageContent>
      </>
    );
  }

  // --- Loading state ---
  if (loading && !data) {
    return (
      <>
        <AdminPageHeader
          breadcrumb={{ label: t("users.title"), to: "/admin/users" }}
        />
        <AdminPageContent>
          <p className="text-sm text-muted-foreground">
            {t("users.detail.loading")}
          </p>
        </AdminPageContent>
      </>
    );
  }

  // No user data and no notFound = generic error
  if (!user) {
    return (
      <>
        <AdminPageHeader
          breadcrumb={{ label: t("users.title"), to: "/admin/users" }}
        />
        <AdminPageContent>
          <div className="space-y-4">
            {errorCode && (
              <p className="text-destructive text-sm" role="alert">
                {t(`errors.${errorCode}`)}
              </p>
            )}
            <Link to="/admin/users">
              <Button variant="outline">Back to users</Button>
            </Link>
          </div>
        </AdminPageContent>
      </>
    );
  }

  // --- Top bar primary action ---
  const topBarAction = (() => {
    if (isSelf) return null;
    if (editing) {
      return (
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={cancelEdit}>
            {t("users.detail.cancel")}
          </Button>
          <Button
            onClick={(e) => {
              void handleSave(e as unknown as FormEvent);
            }}
          >
            <Check className="mr-1.5 size-4" />
            {saving ? t("users.detail.saving") : "Save changes"}
          </Button>
        </div>
      );
    }
    return (
      <Button onClick={startEdit}>{t("users.detail.edit")}</Button>
    );
  })();

  return (
    <>
      <AdminPageHeader
        breadcrumb={{ label: t("users.title"), to: "/admin/users" }}
        title={user.email}
        primaryAction={topBarAction}
      />
      <AdminPageContent>
        {errorCode && (
          <p className="text-destructive text-sm mb-5" role="alert">
            {t(`errors.${errorCode}`)}
          </p>
        )}

        <div className="grid grid-cols-[1fr_300px] gap-5">
          {/* ---- Profile card ---- */}
          <Card className="overflow-visible">
            <CardHeader className="pb-0">
              <div className="flex items-start gap-4">
                {/* Avatar */}
                <div
                  className={`flex size-14 shrink-0 items-center justify-center rounded-full text-lg font-bold ${
                    user.role === "super_admin"
                      ? "bg-primary text-primary-foreground"
                      : "border border-border bg-muted text-foreground"
                  }`}
                >
                  {user.email.charAt(0).toUpperCase()}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-base font-semibold truncate">
                    {user.email}
                  </p>
                  {isSelf && (
                    <p className="text-[13px] text-accent-foreground font-medium">
                      This is you
                    </p>
                  )}
                </div>
                {/* Status pill */}
                <div className="shrink-0 rounded-md bg-muted px-3 py-1.5">
                  <StatusBadge status={user.status} />
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-5">
              <div className="border-t border-border pt-5">
                {editing ? (
                  <EditProfileGrid
                    email={editEmail}
                    role={editRole}
                    roleOpen={roleOpen}
                    onEmailChange={setEditEmail}
                    onRoleChange={setEditRole}
                    onRoleOpenChange={setRoleOpen}
                    error={editError}
                    user={user}
                    t={t}
                  />
                ) : (
                  <ViewProfileGrid user={user} sessions={sessions} t={t} />
                )}
              </div>
            </CardContent>
          </Card>

          {/* ---- Actions card ---- */}
          <div
            data-testid="actions-card"
            className={editing ? "opacity-45 pointer-events-none" : ""}
          >
            <Card>
              <CardHeader className="pb-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  {t("users.detail.actions_heading")}
                </p>
              </CardHeader>
              <CardContent className="space-y-2.5">
                {isSelf ? (
                  <SelfActions />
                ) : (
                  <OtherUserActions
                    isActive={isActive}
                    onResetOpen={() => setResetOpen(true)}
                    onDisableOpen={() => setDisableOpen(true)}
                    onEnableOpen={() => {
                      void handleEnable();
                    }}
                    onDeleteOpen={() => setDeleteOpen(true)}
                    t={t}
                  />
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* ---- Sessions card (full width) ---- */}
        <div className="mt-5">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold">
                    {t("users.detail.sessions_heading")}
                  </CardTitle>
                  <p className="text-[13px] text-muted-foreground mt-0.5">
                    {sessions.length > 0
                      ? `${sessions.length} device${sessions.length !== 1 ? "s" : ""} currently signed in`
                      : ""}
                  </p>
                </div>
                {sessions.length > 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-destructive border-destructive/30 hover:bg-destructive/5"
                    onClick={() => setTerminateAllOpen(true)}
                  >
                    Terminate all
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {!isActive && sessions.length === 0 ? (
                <DisabledSessionsEmptyState />
              ) : sessions.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No active sessions.
                </p>
              ) : (
                <SessionsTable
                  sessions={sessions}
                  onTerminate={(token, label) =>
                    setTerminateSingleOpen({ token, label })
                  }
                />
              )}
            </CardContent>
          </Card>
        </div>
      </AdminPageContent>

      {/* ---- Confirm dialogs ---- */}
      <ConfirmDialog
        open={resetOpen}
        onOpenChange={setResetOpen}
        title={`Reset ${user.email}'s password?`}
        body="A new temporary password will be generated. They'll be signed out everywhere and forced to change it on next sign-in."
        confirmLabel="Reset password"
        onConfirm={() => {
          void handleResetPassword();
        }}
      />
      <ConfirmDialog
        open={disableOpen}
        onOpenChange={setDisableOpen}
        title={`Disable ${user.email}?`}
        body="They'll be signed out of every device and won't be able to sign in until you re-enable them."
        confirmLabel="Disable user"
        onConfirm={() => {
          void handleDisable();
        }}
      />
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={`Delete ${user.email}?`}
        body="This cannot be undone. The account is removed and all sessions terminated. Audit history is preserved."
        confirmLabel="Delete permanently"
        onConfirm={() => {
          void handleDelete();
        }}
      />
      <ConfirmDialog
        open={terminateAllOpen}
        onOpenChange={setTerminateAllOpen}
        title={`Sign ${user.email} out of every device?`}
        body="They'll need to sign in again on each device. Their password is unchanged."
        confirmLabel="Sign out everywhere"
        onConfirm={() => {
          void handleTerminateAll();
        }}
      />
      {terminateSingleOpen && (
        <ConfirmDialog
          open={true}
          onOpenChange={() => setTerminateSingleOpen(null)}
          title="Sign out this device?"
          body={`${terminateSingleOpen.label} will be signed out. Other sessions are unaffected.`}
          confirmLabel="Sign out device"
          onConfirm={() => {
            void handleTerminateSession(terminateSingleOpen.token);
            setTerminateSingleOpen(null);
          }}
        />
      )}

      {/* ---- Temp password modal ---- */}
      {tempPassword && (
        <TempPasswordModal
          email={user.email}
          password={tempPassword}
          onClose={() => {
            setTempPassword(null);
            void refetch();
          }}
        />
      )}
    </>
  );
}

// -------------------------------------------------------------------
// Sub-components
// -------------------------------------------------------------------

interface ViewProfileGridProps {
  user: UserDetailResponse["user"];
  sessions: UserSession[];
  t: (key: string) => string;
}

function deriveLastSignIn(sessions: UserSession[]): string {
  if (sessions.length === 0) return "Never";
  const latest = sessions.reduce((a, b) =>
    new Date(a.last_seen_at) > new Date(b.last_seen_at) ? a : b,
  );
  return formatRelativeTime(latest.last_seen_at);
}

function ViewProfileGrid({ user, sessions, t }: ViewProfileGridProps) {
  const createdFormatted = user.created_at
    ? new Date(user.created_at).toLocaleDateString("en-US", {
        month: "long",
        day: "numeric",
        year: "numeric",
      })
    : "";

  return (
    <dl className="grid grid-cols-3 gap-x-7 gap-y-5 text-sm">
      <div>
        <dt className="text-[13px] text-muted-foreground">
          {t("users.detail.email_label")}
        </dt>
        <dd className="mt-0.5 font-medium">{user.email}</dd>
      </div>
      <div>
        <dt className="text-[13px] text-muted-foreground">
          {t("users.detail.role_label")}
        </dt>
        <dd className="mt-1">
          <RoleBadge role={user.role as UserRole} />
        </dd>
      </div>
      <div>
        <dt className="text-[13px] text-muted-foreground">Status</dt>
        <dd className="mt-1">
          <StatusBadge status={user.status} />
        </dd>
      </div>
      <div>
        <dt className="text-[13px] text-muted-foreground">Created</dt>
        <dd className="mt-0.5 text-muted-foreground">{createdFormatted}</dd>
      </div>
      <div>
        <dt className="text-[13px] text-muted-foreground">Last sign-in</dt>
        <dd className="mt-0.5 text-muted-foreground">
          {deriveLastSignIn(sessions)}
        </dd>
      </div>
      <div>
        <dt className="text-[13px] text-muted-foreground">
          Must change password
        </dt>
        <dd className="mt-0.5">
          {user.force_password_change ? (
            <span className="text-destructive font-medium">Yes</span>
          ) : (
            <span className="text-muted-foreground">No</span>
          )}
        </dd>
      </div>
    </dl>
  );
}

interface EditProfileGridProps {
  email: string;
  role: Role;
  roleOpen: boolean;
  onEmailChange: (v: string) => void;
  onRoleChange: (v: Role) => void;
  onRoleOpenChange: (v: boolean) => void;
  error: string | null;
  user: UserDetailResponse["user"];
  t: (key: string) => string;
}

function EditProfileGrid({
  email,
  role,
  roleOpen,
  onEmailChange,
  onRoleChange,
  onRoleOpenChange,
  error,
  user,
  t,
}: EditProfileGridProps) {
  const roleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!roleOpen) return;
    const handlePointerDown = (e: PointerEvent) => {
      if (roleRef.current && !roleRef.current.contains(e.target as Node)) {
        onRoleOpenChange(false);
      }
    };
    document.addEventListener("pointerdown", handlePointerDown);
    return () => document.removeEventListener("pointerdown", handlePointerDown);
  }, [roleOpen, onRoleOpenChange]);

  return (
    <div className="grid grid-cols-2 gap-x-7 gap-y-5 text-sm">
      <div className="space-y-1.5">
        <Label htmlFor="edit-email">{t("users.detail.email_label")}</Label>
        <Input
          id="edit-email"
          type="email"
          required
          value={email}
          onChange={(e) => onEmailChange(e.target.value)}
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="edit-role">{t("users.detail.role_label")}</Label>
        <div className="relative" ref={roleRef}>
          <button
            id="edit-role"
            type="button"
            onClick={() => onRoleOpenChange(!roleOpen)}
            className="flex h-8 w-full items-center justify-between rounded-lg border border-border bg-background px-3 text-sm outline-none focus:ring-2 focus:ring-primary/20"
          >
            <span>{t(`users.role.${role}`)}</span>
            <ChevronDown className="size-4 text-muted-foreground" />
          </button>
          {roleOpen && (
            <div className="absolute left-0 right-0 top-[calc(100%+4px)] z-50 max-h-[240px] overflow-y-auto rounded-[10px] border border-border bg-background p-1 shadow-xl">
              {(["user", "super_admin"] as const).map((r) => (
                <button
                  key={r}
                  type="button"
                  onClick={() => {
                    onRoleChange(r);
                    onRoleOpenChange(false);
                  }}
                  className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left ${
                    r === role
                      ? "bg-accent text-accent-foreground"
                      : "hover:bg-muted"
                  }`}
                >
                  <div className="flex h-4 w-4 shrink-0 items-center justify-center">
                    {r === role && <Check className="size-3" />}
                  </div>
                  <div className="text-sm font-semibold">
                    {t(`users.role.${r}`)}
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
        {error && (
          <p className="text-destructive text-xs mt-1" role="alert">
            {t(`errors.${error}`)}
          </p>
        )}
      </div>
      {/* Read-only cells */}
      <div>
        <dt className="text-[13px] text-muted-foreground">Last sign-in</dt>
        <dd className="mt-0.5 text-muted-foreground">Never</dd>
      </div>
      <div>
        <dt className="text-[13px] text-muted-foreground">
          Must change password
        </dt>
        <dd className="mt-0.5">
          {user.force_password_change ? (
            <span className="text-destructive font-medium">Yes</span>
          ) : (
            <span className="text-muted-foreground">No</span>
          )}
        </dd>
      </div>
    </div>
  );
}

function SelfActions() {
  return (
    <div className="space-y-3">
      <Link
        to="/change-password"
        className="flex h-8 w-full items-center gap-2.5 rounded-lg border border-border px-3 text-sm font-medium text-primary hover:bg-muted"
      >
        <Lock className="size-4" />
        Change your password
      </Link>
      <p className="text-xs text-muted-foreground leading-relaxed">
        Disable and delete are hidden on your own account. To remove yourself,
        have another administrator do it — or promote a new admin first.
      </p>
    </div>
  );
}

interface OtherUserActionsProps {
  isActive: boolean;
  onResetOpen: () => void;
  onDisableOpen: () => void;
  onEnableOpen: () => void;
  onDeleteOpen: () => void;
  t: (key: string) => string;
}

function OtherUserActions({
  isActive,
  onResetOpen,
  onDisableOpen,
  onEnableOpen,
  onDeleteOpen,
  t,
}: OtherUserActionsProps) {
  return (
    <>
      <Button
        variant="outline"
        className="w-full justify-start gap-2.5"
        onClick={onResetOpen}
      >
        <Lock className="size-4" />
        {t("users.detail.reset_password")}
      </Button>

      {isActive ? (
        <Button
          variant="outline"
          className="w-full justify-start gap-2.5"
          onClick={onDisableOpen}
        >
          <Ban className="size-4" />
          {t("users.detail.disable")}
        </Button>
      ) : (
        <Button
          className="w-full justify-start gap-2.5"
          onClick={onEnableOpen}
        >
          <Check className="size-4" />
          {t("users.detail.enable")}
        </Button>
      )}

      <div className="border-t border-border my-1" />

      <Button
        variant="outline"
        className="w-full justify-start gap-2.5 text-destructive border-destructive/30 hover:bg-destructive/5"
        onClick={onDeleteOpen}
      >
        <Trash2 className="size-4" />
        {t("users.detail.delete")}
      </Button>
    </>
  );
}

function DisabledSessionsEmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-10 text-center">
      <div className="flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground mb-3">
        <Laptop className="size-5" />
      </div>
      <p className="text-sm font-medium">No active sessions</p>
      <p className="text-[13px] text-muted-foreground mt-1">
        All sessions were terminated when this user was disabled.
      </p>
    </div>
  );
}

interface SessionsTableProps {
  sessions: UserSession[];
  onTerminate: (token: string, deviceLabel: string) => void;
}

function SessionsTable({ sessions, onTerminate }: SessionsTableProps) {
  return (
    <Table>
      <TableHeader>
        <TableRow className="bg-sidebar">
          <TableHead className="text-xs font-semibold uppercase tracking-wider">
            Device
          </TableHead>
          <TableHead className="text-xs font-semibold uppercase tracking-wider">
            IP
          </TableHead>
          <TableHead className="text-xs font-semibold uppercase tracking-wider">
            Started
          </TableHead>
          <TableHead className="text-xs font-semibold uppercase tracking-wider">
            Last seen
          </TableHead>
          <TableHead className="text-xs font-semibold uppercase tracking-wider w-[120px]" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {sessions.map((session) => {
          const device = parseDevice(session.user_agent);
          const DeviceIcon =
            device.icon === "phone" ? Smartphone : Laptop;
          return (
            <TableRow key={session.token}>
              <TableCell>
                <div className="flex items-center gap-2.5">
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                    <DeviceIcon className="size-4" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate">
                      {device.label}
                    </p>
                    <p
                      className="text-xs text-muted-foreground font-mono truncate max-w-[240px]"
                      title={session.user_agent}
                    >
                      {session.user_agent}
                    </p>
                  </div>
                </div>
              </TableCell>
              <TableCell className="font-mono text-[13px]">
                {session.ip_address}
              </TableCell>
              <TableCell className="text-[13px] text-muted-foreground">
                {formatRelativeTime(session.created_at)}
              </TableCell>
              <TableCell className="text-[13px] text-muted-foreground">
                {formatRelativeTime(session.last_seen_at)}
              </TableCell>
              <TableCell>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 text-xs"
                  onClick={() => onTerminate(session.token, device.label)}
                >
                  Terminate
                </Button>
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
