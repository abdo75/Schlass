import { useTranslation } from "react-i18next";

export type UserRole = "super_admin" | "user";

export function RoleBadge({ role }: { role: UserRole }) {
  const { t } = useTranslation();
  const isAdmin = role === "super_admin";
  return (
    <span
      className={`inline-flex h-6 items-center rounded-md px-2.5 text-xs font-semibold ${
        isAdmin
          ? "bg-accent text-accent-foreground"
          : "bg-muted text-foreground"
      }`}
    >
      {t(`users.role.${role}`)}
    </span>
  );
}
