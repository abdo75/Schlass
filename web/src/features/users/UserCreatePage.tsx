import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createUser } from "./api";

type Role = "super_admin" | "user";

export function UserCreatePage() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("user");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorCode(null);
    setSubmitting(true);
    try {
      const res = await createUser(email, role);
      void navigate(`/admin/users/${res.user.id}`);
    } catch (err: unknown) {
      const code =
        err && typeof err === "object" && "code" in err
          ? String((err as { code: unknown }).code)
          : "INTERNAL_ERROR";
      setErrorCode(code);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="max-w-xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold">{t("users.create.title")}</h1>
        <p className="text-sm text-muted-foreground">
          {t("users.create.description")}
        </p>
      </div>

      <form
        onSubmit={(e) => {
          void handleSubmit(e);
        }}
        className="space-y-4"
      >
        <div className="space-y-2">
          <Label htmlFor="email">{t("users.create.email_label")}</Label>
          <Input
            id="email"
            type="email"
            autoComplete="off"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="password">{t("users.create.password_label")}</Label>
          <Input
            id="password"
            type="password"
            autoComplete="new-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            {t("users.create.password_hint")}
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="role">{t("users.create.role_label")}</Label>
          <select
            id="role"
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
            className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
          >
            <option value="user">{t("users.role.user")}</option>
            <option value="super_admin">{t("users.role.super_admin")}</option>
          </select>
        </div>

        {errorCode && (
          <p className="text-destructive text-sm" role="alert">
            {t(`errors.${errorCode}`)}
          </p>
        )}

        <div className="flex items-center gap-2">
          <Button type="submit" disabled={submitting}>
            {submitting
              ? t("users.create.submitting")
              : t("users.create.submit")}
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              void navigate("/admin/users");
            }}
          >
            {t("users.create.cancel")}
          </Button>
        </div>
      </form>
    </div>
  );
}
