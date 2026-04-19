import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";

export function SigningKeysPage() {
  return (
    <>
      <AdminPageHeader title="Signing keys" />
      <AdminPageContent>
        <p className="text-sm text-muted-foreground">Signing keys page — implemented in M11.</p>
      </AdminPageContent>
    </>
  );
}
