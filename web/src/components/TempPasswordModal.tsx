import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { LockKeyhole, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/CopyButton";
import { cn } from "@/lib/utils";

interface TempPasswordModalProps {
  email: string;
  password: string;
  onClose: () => void;
}

export function TempPasswordModal({
  email,
  password,
  onClose,
}: TempPasswordModalProps) {
  const { t } = useTranslation();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    window.addEventListener("keydown", handler, true);
    return () => {
      window.removeEventListener("keydown", handler, true);
    };
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-foreground/30 backdrop-blur-sm" />
      <div className="relative z-10 w-full max-w-md rounded-xl border border-border bg-background shadow-lg">
        {/* Header */}
        <div className="flex items-start gap-4 px-7 pt-7 pb-5">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-[10px] bg-accent text-accent-foreground">
            <LockKeyhole className="size-5" />
          </div>
          <div className="flex flex-col gap-0.5">
            <span className="text-lg font-semibold leading-tight">
              {t("users.create.temp_password_modal.title")}
            </span>
            <span className="text-[13px] text-muted-foreground">
              {t("users.create.temp_password_modal.subtitle", { email })}
            </span>
          </div>
        </div>

        {/* Password block */}
        <div className="px-7">
          <div
            className={cn(
              "flex h-14 items-center gap-3 rounded-[10px] border border-border bg-sidebar px-4",
            )}
          >
            <code className="flex-1 break-all font-mono text-[15px] leading-snug">
              {password}
            </code>
            <CopyButton value={password} label="temporary password" size="md" />
          </div>
        </div>

        {/* Warning callout */}
        <div className="px-7 pt-4">
          <div className="flex items-start gap-2.5 rounded-[10px] border border-warning-border bg-warning px-4 py-3 text-warning-foreground">
            <TriangleAlert className="mt-px size-4 shrink-0" />
            <span className="text-[13px] leading-snug">
              {t("users.create.temp_password_modal.warning")}
            </span>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end px-7 py-6">
          <Button variant="default" onClick={onClose}>
            {t("users.create.temp_password_modal.done")}
          </Button>
        </div>
      </div>
    </div>
  );
}
