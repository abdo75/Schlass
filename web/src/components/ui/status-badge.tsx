import { useTranslation } from "react-i18next";

export type UserStatus = "active" | "disabled";

interface StatusBadgeProps {
  status: UserStatus;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const { t } = useTranslation();
  const isActive = status === "active";
  return (
    <span
      className={`inline-flex items-center gap-2 text-sm ${
        isActive ? "" : "text-muted-foreground"
      }`}
    >
      <span
        data-testid="status-dot"
        className={`inline-block h-2 w-2 shrink-0 rounded-full ${
          isActive ? "bg-primary" : "bg-destructive"
        }`}
      />
      {t(`users.status.${status}`)}
    </span>
  );
}
