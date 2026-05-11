import { SkeletonBar } from "@/components/PageSkeleton";

const ROW_COUNT = 4;

export function PickerSkeleton() {
  return (
    <div data-testid="audit-picker-skeleton" aria-hidden="true" role="presentation" className="grid gap-2 py-2">
      {Array.from({ length: ROW_COUNT }, (_, i) => (
        <div key={i} className="flex items-center justify-between gap-3 rounded-md px-2 py-2">
          <SkeletonBar w="65%" h={14} />
          <SkeletonBar w={28} h={12} />
        </div>
      ))}
    </div>
  );
}
