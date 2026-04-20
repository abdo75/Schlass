interface Props {
  value: string;
  onChange: (next: string) => void;
  dirty: boolean;
}

// GeneralTab renders the Instance card from the approved mockup. Single
// field (instance_name). The dirty-dot next to the label is the
// scroll-back orientation cue — admin can see which row is pending save
// even if they've scrolled the card out of view.
export function GeneralTab({ value, onChange, dirty }: Props) {
  return (
    <div className="mb-4 rounded-xl border border-border bg-background overflow-hidden">
      <div className="px-6 pt-5 pb-1">
        <h3 className="text-[15px] font-semibold">Instance</h3>
        <p className="mt-1 text-[13px] text-muted-foreground leading-relaxed">
          Display name for this Schlass deployment. Appears on the login card, in the browser tab title, and in
          transactional email subjects.
        </p>
      </div>
      <div className="px-6 pt-[14px] pb-5 flex flex-col gap-[14px]">
        <div className="grid grid-cols-[1fr_auto] items-center gap-5">
          <label htmlFor="instance-name" className="text-[13.5px] font-medium">
            Instance name
            {dirty && (
              <span
                className="inline-block w-1.5 h-1.5 rounded-full ml-2 align-middle"
                style={{ background: "oklch(0.76 0.15 80)" }}
                aria-hidden="true"
              />
            )}
          </label>
          <input
            id="instance-name"
            type="text"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            className="h-[34px] w-[340px] border border-border rounded-md px-3 text-[13.5px] bg-background text-foreground focus:outline-0 focus:border-primary focus:ring-2 focus:ring-primary/20"
            maxLength={64}
          />
        </div>
      </div>
    </div>
  );
}
