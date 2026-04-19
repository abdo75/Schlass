import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";

export function ClientCreatePage() {
  return (
    <>
      <AdminPageHeader
        breadcrumbPath={[
          { label: "Clients", to: "/admin/clients" },
          { label: "New client" },
        ]}
      />
      <AdminPageContent>
        <p className="text-sm text-muted-foreground">Create form — implemented in M10.</p>
      </AdminPageContent>
    </>
  );
}
