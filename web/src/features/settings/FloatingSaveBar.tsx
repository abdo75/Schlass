interface FloatingSaveBarProps {
  dirtyCount: number;
  onSave: () => void;
  onDiscard: () => void;
  saving: boolean;
}

// FloatingSaveBar is viewport-fixed at the bottom. Appears only when
// dirtyCount > 0, scrolls with the viewport (always visible). Rail offsets
// by the admin sidebar width (220px, unconditional — see AdminLayout.tsx
// line 108) so the bar spans the main column, not under the sidebar.
// Content scroll clearance is guaranteed by `pb-28` on the SettingsPage
// card column — last card always clears the bar height.
// Consumes --page-max-w and --page-gutter CSS vars declared on the parent
// so the bar width tracks the card column exactly.
export function FloatingSaveBar({ dirtyCount, onSave, onDiscard, saving }: FloatingSaveBarProps) {
  if (dirtyCount === 0) return null;
  return (
    <div
      className="pointer-events-none fixed left-[220px] right-0 bottom-5 z-30"
      style={{ padding: "0 var(--page-gutter)" }}
      role="status"
      aria-live="polite"
    >
      <div
        className="pointer-events-auto mx-auto flex items-center justify-between gap-4 rounded-xl border border-border bg-background px-4 py-2.5 shadow-[0_12px_32px_-12px_rgba(0,0,0,0.12),_0_4px_10px_-4px_rgba(0,0,0,0.06)]"
        style={{ maxWidth: "var(--page-max-w)" }}
      >
        <div className="flex items-center gap-2.5 text-[13px] font-medium text-foreground">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: "oklch(0.76 0.15 80)" }}
            aria-hidden="true"
          />
          {dirtyCount} unsaved {dirtyCount === 1 ? "change" : "changes"}
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onDiscard}
            disabled={saving}
            className="h-[30px] border border-border bg-transparent text-muted-foreground rounded-md px-3.5 text-[13px] font-medium hover:text-foreground hover:bg-muted hover:border-muted-foreground/30 disabled:opacity-50"
          >
            Discard
          </button>
          <button
            type="button"
            onClick={onSave}
            disabled={saving}
            className="h-[30px] bg-primary text-primary-foreground border-0 rounded-md px-4 text-[13px] font-semibold hover:bg-primary/90 disabled:opacity-50"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
