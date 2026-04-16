interface SkeletonBarProps {
  w: number | string;
  h: number;
  circle?: boolean;
  className?: string;
}

export function SkeletonBar({ w, h, circle, className = "" }: SkeletonBarProps) {
  return (
    <div
      className={`schlass-shimmer bg-muted ${circle ? "rounded-full" : "rounded"} ${className}`}
      style={{ width: typeof w === "number" ? `${w}px` : w, height: `${h}px` }}
    />
  );
}

export function UsersTableSkeleton() {
  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <SkeletonBar w={100} h={20} />
        <SkeletonBar w={160} h={12} />
      </div>
      <SkeletonBar w="100%" h={32} className="max-w-[400px]" />
      <div className="overflow-hidden rounded-xl border border-border bg-background">
        <div className="grid grid-cols-[1fr_120px_120px_140px_40px] gap-3 border-b border-border bg-sidebar px-6 py-3">
          {[0, 1, 2, 3, 4].map((i) => (
            <SkeletonBar key={i} w={60} h={10} />
          ))}
        </div>
        {[0, 1, 2].map((row) => (
          <div
            key={row}
            className="grid grid-cols-[1fr_120px_120px_140px_40px] items-center gap-3 border-b border-border px-6 py-4 last:border-b-0"
          >
            <div className="flex items-center gap-3">
              <SkeletonBar w={36} h={36} circle />
              <SkeletonBar w="60%" h={14} />
            </div>
            <SkeletonBar w={50} h={20} />
            <SkeletonBar w={70} h={14} />
            <SkeletonBar w={80} h={14} />
            <div />
          </div>
        ))}
      </div>
    </div>
  );
}
