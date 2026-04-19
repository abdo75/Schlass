import { useParams } from "react-router-dom";
import { AdminPageHeader, AdminPageContent } from "@/components/AdminLayout";

export function ClientDetailPage() {
  const { id } = useParams<{ id: string }>();
  return (
    <>
      <AdminPageHeader
        breadcrumbPath={[
          { label: "Clients", to: "/admin/clients" },
          { label: id ?? "…" },
        ]}
      />
      <AdminPageContent>
        <p className="text-sm text-muted-foreground">Detail view — implemented in M11.</p>
      </AdminPageContent>
    </>
  );
}
