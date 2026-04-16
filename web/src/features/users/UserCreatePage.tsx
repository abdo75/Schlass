import { useState, useEffect, useRef, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { ChevronDown, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";
import { TempPasswordModal } from "@/components/TempPasswordModal";
import { createUser, type CreateUserResponse } from "./api";

type Role = "user" | "super_admin";

export function UserCreatePage() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("user");
  const [roleOpen, setRoleOpen] = useState(false);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [modalData, setModalData] = useState<{
    user: CreateUserResponse["user"];
    temporary_password: string;
  } | null>(null);
  const roleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!roleOpen) return;
    const handlePointerDown = (e: PointerEvent) => {
      if (roleRef.current && !roleRef.current.contains(e.target as Node)) {
        setRoleOpen(false);
      }
    };
    document.addEventListener("pointerdown", handlePointerDown);
    return () => document.removeEventListener("pointerdown", handlePointerDown);
  }, [roleOpen]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorCode(null);
    setSubmitting(true);
    try {
      const res = await createUser(email, role);
      setModalData({ user: res.user, temporary_password: res.temporary_password });
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

  const handleModalClose = () => {
    if (modalData) {
      void navigate(`/admin/users/${modalData.user.id}`);
    }
  };

  return (
    <>
      <AdminPageHeader
        breadcrumb={{ label: t("users.title"), to: "/admin/users" }}
      />
      <AdminPageContent>
        <div className="flex justify-center pt-8">
          <div className="w-full max-w-[448px]">
            <Card className="overflow-visible">
              <CardHeader>
                <CardTitle className="text-[20px]">
                  {t("users.create.title")}
                </CardTitle>
                <CardDescription className="text-[13px]">
                  {t("users.create.description")}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form
                  id="create-user-form"
                  onSubmit={(e) => {
                    void handleSubmit(e);
                  }}
                  className="space-y-4"
                >
                  <div className="space-y-1.5">
                    <Label htmlFor="email">{t("users.create.email_label")}</Label>
                    <Input
                      id="email"
                      type="email"
                      autoComplete="off"
                      placeholder="name@example.com"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                  </div>

                  <div className="space-y-1.5">
                    <Label>{t("users.create.role_label")}</Label>
                    <div className="relative" ref={roleRef}>
                      <button
                        type="button"
                        onClick={() => setRoleOpen((v) => !v)}
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
                                setRole(r);
                                setRoleOpen(false);
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
                              <div>
                                <div className="text-sm font-semibold">
                                  {t(`users.role.${r}`)}
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {t(`users.create.role_description.${r}`)}
                                </div>
                              </div>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {errorCode && (
                    <p className="text-destructive text-sm" role="alert">
                      {t(`errors.${errorCode}`)}
                    </p>
                  )}
                </form>
              </CardContent>
              <CardFooter className="flex items-center justify-end gap-2 border-t border-border pt-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    void navigate("/admin/users");
                  }}
                >
                  {t("users.create.cancel")}
                </Button>
                <Button
                  type="submit"
                  form="create-user-form"
                  disabled={submitting}
                >
                  {submitting
                    ? t("users.create.submitting")
                    : t("users.create.submit")}
                </Button>
              </CardFooter>
            </Card>
          </div>
        </div>
      </AdminPageContent>

      {modalData && (
        <TempPasswordModal
          email={modalData.user.email}
          password={modalData.temporary_password}
          onClose={handleModalClose}
        />
      )}
    </>
  );
}
