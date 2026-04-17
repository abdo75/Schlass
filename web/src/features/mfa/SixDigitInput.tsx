import { useRef, useEffect, type KeyboardEvent, type ClipboardEvent, type ChangeEvent } from "react";

interface Props {
  value: string;
  onChange: (next: string) => void;
  autoFocus?: boolean;
  disabled?: boolean;
}

// SixDigitInput renders six per-digit boxes with auto-advance, backspace-on-
// empty focus-back, and paste support. `value` is the full 0-6 char string;
// `onChange` fires on every digit add/remove.
export function SixDigitInput({ value, onChange, autoFocus, disabled }: Props) {
  const refs = useRef<Array<HTMLInputElement | null>>([]);

  useEffect(() => {
    if (autoFocus) refs.current[0]?.focus();
  }, [autoFocus]);

  const set = (i: number, el: HTMLInputElement | null) => {
    refs.current[i] = el;
  };

  const handleInput = (i: number) => (e: ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value.replace(/\D/g, "");
    if (raw.length === 0) {
      const next = value.slice(0, i) + "" + value.slice(i + 1);
      onChange(next);
      return;
    }
    // Take the last typed digit (handles overwrite when user types into filled box).
    const digit = raw[raw.length - 1];
    const next = (value.slice(0, i) + digit + value.slice(i + 1)).slice(0, 6);
    onChange(next);
    if (i < 5) refs.current[i + 1]?.focus();
  };

  const handleKey = (i: number) => (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && (refs.current[i]?.value ?? "") === "" && i > 0) {
      refs.current[i - 1]?.focus();
    }
  };

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const raw = (e.clipboardData.getData("text") || "").replace(/\D/g, "").slice(0, 6);
    if (!raw) return;
    e.preventDefault();
    onChange(raw);
    refs.current[Math.min(raw.length, 5)]?.focus();
  };

  return (
    <div className="flex justify-center gap-[6px]">
      {[0, 1, 2, 3, 4, 5].map((i) => {
        const ch = value[i] ?? "";
        const filled = ch !== "";
        // Gap between box 3 and box 4
        const extraMargin = i === 3 ? "ml-[14px]" : "";
        return (
          <input
            key={i}
            ref={(el) => set(i, el)}
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={1}
            value={ch}
            disabled={disabled}
            onChange={handleInput(i)}
            onKeyDown={handleKey(i)}
            onPaste={handlePaste}
            className={`h-[52px] w-[42px] rounded-[5px] border-[1.5px] text-center font-mono text-[22px] font-semibold outline-none transition ${extraMargin} ${
              filled
                ? "border-primary bg-primary/5 text-foreground"
                : "border-border text-muted-foreground/30"
            } focus:border-primary focus:bg-primary/5`}
            placeholder="·"
            aria-label={`Digit ${i + 1}`}
          />
        );
      })}
    </div>
  );
}
