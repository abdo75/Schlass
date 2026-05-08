# Session 01 — Theming + design-system reconciliation

**Findings addressed:** B1, B2, M7 (style only), M15, M16, M20 (CSS port).
**Estimated effort:** 4–6 hours.
**Order:** must run first.

## Scope

Port the bespoke `index.css` audit-panel block to design-system tokens. Make dark mode work. Replace literal Tailwind palette with `--warning` token. Reconcile tab style with `SettingsPage`. Codify a single modal backdrop recipe. Add focus-visible rings.

## Files in scope (whitelist — only edit these)

- `web/src/index.css` (heavy edit on lines 162–516)
- `web/src/features/audit/AuditTimeline.tsx` (chip color classes only — do NOT touch ARIA/keyboard yet, that's S2)
- `web/src/features/audit/AuditTabs.tsx` (style only — do NOT touch ARIA tab pattern, that's S2)
- `web/src/features/audit/AuditPanel.tsx` (only the inline backdrop classes; do NOT add focus trap yet — S2)
- `web/src/features/audit/StepUpModal.tsx` (only backdrop class unification; do NOT add focus trap — S2)
- `web/src/features/audit/__snapshots__/AuditPanel.test.tsx.snap` (regenerate if class names changed; verify diff is style-only)

**Do NOT touch:** any picker logic, any state hooks, any i18n strings, any `.test.tsx` behavior tests.

## Tasks

1. **B1: Port panel CSS to tokens.** Replace every `oklch(...)` literal in `index.css:162-516` with `var(--color-...)` token references. Inventory of literals to migrate:
   - `oklch(0.20 0 0)` → `var(--color-foreground)`
   - `oklch(0.99 0 0)` → `var(--color-card)` or `var(--color-background)` per context
   - `oklch(0.34 0.12 185)` → `var(--color-primary)`
   - `oklch(0.47 0.22 27)` → `var(--color-destructive)`
   - shadow `oklch(0.145 0 0 / 0.06)` → keep as-is (shadow alpha is OK fixed) OR define a shared `--shadow-elevated` token in `:root` + `.dark`.
   - backdrop `oklch(0.145 0 0 / 0.30)` → see task 4 (unified backdrop).

   For any literal that has no equivalent semantic token, ADD the token to `:root` and `.dark` blocks (e.g. `--panel-diff-added-bg` / `--panel-diff-added-fg` pair) rather than leaving the literal.

2. **B1 (cont): Add `.dark` overrides.** Whatever cannot be expressed via existing tokens — add explicit `.dark` block at the bottom of `index.css` overriding the new panel-specific tokens. Acceptance: toggle `.dark` class on `<html>` in DevTools → panel remains legible (text contrast ≥ WCAG AA on every block, callout, diff cell, fact row).

3. **B2: Replace `bg-amber-*` literals.** In `AuditTimeline.tsx`:
   - `:108` (GDPR badge) → `bg-warning text-warning-foreground border border-warning-border`
   - `:139` denied chip bg/text → `bg-warning text-warning-foreground`
   - `:144` denied dot → `bg-[--warning-border]` (or define a `bg-warning-strong` utility if dot needs more saturation)

4. **M15: Single modal backdrop.** Pick one recipe and apply everywhere:
   - **Recommended:** `bg-foreground/35 backdrop-blur-sm` (matches `ConfirmDialog.tsx:45`).
   - Apply in `AuditPanel.tsx` overlay, `StepUpModal.tsx` overlay, and panel CSS overlay rule.
   - Remove the literal `oklch(0.145 0 0 / 0.30)` from `index.css`.

5. **M16: Focus-visible rings.** Add to `.panel-close`, `.panel-btn`, `.panel-fact-link` in `index.css`:
   ```css
   &:focus-visible {
       outline: none;
       box-shadow: 0 0 0 3px var(--color-ring) / 0.5;
   }
   ```
   Or rewrite as Tailwind utilities (`focus-visible:ring-3 focus-visible:ring-ring/50`) if the elements move to utility-class styling.

6. **M7 (style half): AuditTabs underline style.** Replace `rounded-md bg-accent text-accent-foreground` pill with the `border-b-2 border-primary` underline pattern from `SettingsPage.tsx:269-285`. Match padding/gap exactly; reuse the same class string if practical.

7. **M20 partial: Optional CSS-to-Tailwind port.** If time permits, migrate parts of the panel CSS block to Tailwind utilities directly in `AuditPanel.tsx` JSX. Do not over-reach — primary win is the token migration above.

## Acceptance criteria

```bash
cd web
npm run lint              # 0 issues
npx tsc -b                # clean
npm run test -- --run     # all green; AuditPanel snapshot may need regen — diff must be class-name-only
```

Visual:
- Toggle `.dark` on `<html>`: panel text legible, diff cells readable, callouts visible against background.
- Run `npm run dev`, navigate to `/admin/audit`, open detail panel, hit Tab/Shift+Tab — every interactive element shows a visible focus ring.
- AuditTabs in `/admin/audit` and `/admin/settings` use the same visual style.
- All three modals (AuditPanel, StepUpModal, ConfirmDialog) have identical backdrop appearance.

## Commit shape

```
fix(audit-fe): S01 — port panel CSS to tokens, dark mode, unified backdrop
```

One commit if the diff is coherent; up to three commits if logical (CSS-port / chip-colors / tabs-style) helps review.

## Memory pointer to update

After landing, append to `MEMORY.md`:
```
- [Audit FE fixup progress](project_audit_fe_fixup_progress.md) — S01 done at <commit>; next = S02 a11y
```
