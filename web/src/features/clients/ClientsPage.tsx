import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";

export function ClientsPage() {
  return (
    <>
      <AdminPageHeader title="OIDC Clients" />
      <AdminPageContent>
        <p className="text-sm text-muted-foreground">List view — implemented in M9.</p>
      </AdminPageContent>
    </>
  );
}
