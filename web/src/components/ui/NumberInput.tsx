import { useCallback } from "react";

interface NumberInputProps {
  value: number;
  onChange: (next: number) => void;
  min?: number;
  max?: number;
  ariaLabel?: string;
  className?: string;
}

// Shared number-input with inline chevron steppers. Hides the browser's
// native spinner; 90px wide by default. Used in every admin Settings tab
// that has integer fields (password_min_length, lockout_threshold, token
// TTLs, SMTP port, etc.).
export function NumberInput({ value, onChange, min, max, ariaLabel, className = "" }: NumberInputProps) {
  const step = useCallback(
    (delta: number) => {
      let next = value + delta;
      if (min !== undefined && next < min) next = min;
      if (max !== undefined && next > max) next = max;
      onChange(next);
    },
    [value, min, max, onChange],
  );

  return (
    <span
      className={
        "inline-flex items-stretch h-8 border border-border rounded-md bg-background overflow-hidden w-[90px] focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/20 " +
        className
      }
    >
      <input
        type="number"
        value={value}
        onChange={(e) => {
          const n = Number(e.target.value);
          if (!Number.isNaN(n)) onChange(n);
        }}
        min={min}
        max={max}
        aria-label={ariaLabel}
        className="flex-1 min-w-0 border-0 outline-0 px-2.5 text-[13.5px] tabular-nums text-right text-foreground bg-transparent [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
      />
      <span className="flex flex-col border-l border-border w-5">
        <button
          type="button"
          onClick={() => step(1)}
          aria-label={ariaLabel ? `Increase ${ariaLabel}` : "Increase"}
          className="flex-1 border-0 bg-background cursor-pointer grid place-items-center text-muted-foreground hover:bg-muted hover:text-foreground"
        >
          <svg viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-2 h-2">
            <path d="M2 6L5 3L8 6" />
          </svg>
        </button>
        <button
          type="button"
          onClick={() => step(-1)}
          aria-label={ariaLabel ? `Decrease ${ariaLabel}` : "Decrease"}
          className="flex-1 border-0 bg-background cursor-pointer grid place-items-center text-muted-foreground hover:bg-muted hover:text-foreground border-t border-border"
        >
          <svg viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.6" className="w-2 h-2">
            <path d="M2 4L5 7L8 4" />
          </svg>
        </button>
      </span>
    </span>
  );
}
