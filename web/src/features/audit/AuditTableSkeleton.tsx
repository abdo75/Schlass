import { SkeletonBar } from "@/components/PageSkeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const ROW_COUNT = 8;

export function AuditTableSkeleton() {
  return (
    <div
      data-testid="audit-table-skeleton"
      aria-hidden="true"
      className="overflow-hidden rounded-lg border border-border bg-background"
    >
      <Table>
        <TableHeader className="bg-muted/35">
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-[110px] px-4 py-3"><SkeletonBar w={60} h={10} /></TableHead>
            <TableHead className="w-[140px] px-4 py-3"><SkeletonBar w={70} h={10} /></TableHead>
            <TableHead className="px-4 py-3"><SkeletonBar w={80} h={10} /></TableHead>
            <TableHead className="w-[190px] px-4 py-3"><SkeletonBar w={70} h={10} /></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: ROW_COUNT }, (_, i) => (
            <TableRow key={i} className="hover:bg-transparent">
              <TableCell className="px-4 py-3"><SkeletonBar w={70} h={20} className="rounded-full" /></TableCell>
              <TableCell className="px-4 py-3"><SkeletonBar w={90} h={12} /></TableCell>
              <TableCell className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <SkeletonBar w="60%" h={14} className="max-w-[280px]" />
                  <SkeletonBar w={120} h={14} />
                </div>
              </TableCell>
              <TableCell className="px-4 py-3"><SkeletonBar w={150} h={12} /></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
