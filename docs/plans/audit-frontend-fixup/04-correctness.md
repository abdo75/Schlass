# Session 04 — Correctness, state, data layer

**Findings addressed:** B6, B8, M1, M2, M3 (logic half), M6, M8, M9, M10, M11 (state-reset half), M12, M13, M17, M18, M19.
**Estimated effort:** 5–7 hours.
**Order:** after S03 lands.

## Scope

Fix bugs and shore up data flow. URL state validation. Wire or remove `selectedEventId`. Extract `usePickerFetch` hook. Dedupe `OutcomeChip`. Add export error handling + double-submit guard. Calendar from/to swap. Runtime shape guards. StepUpModal state reset. Filter-bar hydration race.

## Files in scope (whitelist)

- `web/src/features/audit/useUrlState.ts`
- `web/src/features/audit/useAuditQuery.ts`
- `web/src/features/audit/types.ts`
- `web/src/features/audit/AuditPage.tsx`
- `web/src/features/audit/AuditPanel.tsx` (clipboard/export blob handling only)
- `web/src/features/audit/AuditPanelHelpers.tsx` (non-null assertions, OutcomeChip merge)
- `web/src/features/audit/AuditPanelModules.tsx` (non-null assertion, scopes guard)
- `web/src/features/audit/AuditTimeline.tsx` (delete duplicate `OutcomeChip`)
- `web/src/features/audit/AuditFilterBar.tsx` (hydration effect; pill dedupe)
- `web/src/features/audit/AuditCalendar.tsx` (from/to swap)
- `web/src/features/audit/ActorPicker.tsx`
- `web/src/features/audit/TargetPicker.tsx`
- `web/src/features/audit/StepUpModal.tsx` (state-reset only; a11y already done in S02)
- `web/src/features/audit/ExportMenu.tsx`
- new file: `web/src/features/audit/usePickerFetch.ts`
- corresponding `*.test.tsx` updates

**Do NOT touch:** styling, ARIA, i18n strings (those landed in S01–S03; just keep them intact while refactoring).

## Tasks

1. **B8: Validate URL casts.** In `useUrlState.ts:8,15`:
   ```ts
   const VIEW_VALUES = ["all", "auth", "admin", "system"] as const; // adjust to actual enum
   const OUTCOME_VALUES = ["success", "denied", "error"] as const;
   const view = VIEW_VALUES.includes(raw as any) ? raw as AuditState["view"] : "all";
   const outcome = OUTCOME_VALUES.includes(rawOutcome as any) ? rawOutcome as Outcome : undefined;
   ```
   Pick actual valid values from `types.ts` enum. Same defensive pattern for any other enum field parsed from URL.

2. **M1: Wire or remove `selectedEventId`.**
   - **Recommendation: wire it.** In `AuditPage.tsx`, after `useAuditList` returns data, add `useEffect`:
     ```ts
     useEffect(() => {
       if (state.selectedEventId && list.data && !selected) {
         const found = list.data.items.find(i => i.id === state.selectedEventId);
         if (found) setSelected(found);
       }
     }, [state.selectedEventId, list.data, selected]);
     ```
   - When `setSelected(item)` is called from the row click, also call `set({ selectedEventId: item.id })` to keep URL ↔ panel state in sync.
   - When closing the panel (`setSelected(null)`), call `set({ selectedEventId: undefined })`.
   - Test: paste `?event=<id>` URL → panel auto-opens.

3. **M2: Single canonical OutcomeChip.** Delete the private `OutcomeChip` in `AuditTimeline.tsx:134`. Use the exported one from `AuditPanelHelpers.tsx:5`. Reconcile prop signature: extend the helpers version to accept either `onClick` (mouse-event) or `onFilter` (Outcome callback) — or simpler, normalize all callers to one signature. Easiest: pass `(o) => onOutcomeFilter(o)` from the timeline column instead of stopping the row's onClick propagation.

4. **M3: Extract `usePickerFetch<T>` hook.** Create `web/src/features/audit/usePickerFetch.ts`:
   ```ts
   export function usePickerFetch<T>(url: string, params: URLSearchParams) {
     // Mirror useAuditQuery's stable-key + AbortController pattern.
     // Return { data, loading, error, retry }.
   }
   ```
   Refactor `ActorPicker.tsx` and `TargetPicker.tsx` to use it. Restrict the params dependency to picker-relevant fields only (NOT full `state` — exclude `page`, `view`, `selectedEventId`).

5. **M12: Filter-bar hydration race.** In `AuditFilterBar.tsx:27-40`:
   - Replace `useEffect(..., [state, targetDisplay])` with a one-shot mount-guarded ref: `const hydrated = useRef(false); useEffect(() => { if (hydrated.current || !state.target_id) return; hydrated.current = true; /* fetch + set */ }, [state.target_id, state.target_type])`.
   - In the picker `find` predicate, match on BOTH `target_type` AND `target_id` to guard against id collisions across types.
   - Once `usePickerFetch` exists, prefer using it instead of a bare fetch.

6. **M13: Pill dedupe.** Extract `web/src/features/audit/Pill.tsx`:
   ```tsx
   type PillProps = { variant: "dashed" | "active" | "openerActive"; children; onClick?; ariaLabel?; ... };
   ```
   Replace `Opener`, `ActiveChip`, `ActiveOpener` in `AuditFilterBar.tsx:223,237,259` with `<Pill>` calls.

7. **B6: ExportMenu error + double-submit.**
   - Wrap `download(fmt)` body in try/catch:
     ```ts
     try { /* existing logic */ }
     catch (err) {
       toast.error(err instanceof ApiRequestError ? `Export failed: ${err.body.message}` : "Export failed.");
     }
     finally { setPendingFormat(null); }
     ```
     Use `sonner` toast (already imported elsewhere). Keep the STEPUP_REQUIRED early-return path intact.
   - Disable trigger button while `pendingFormat !== null`.
   - On success, fire `toast.success(...)` instead of relying on the persistent `lastManifest` footer (the footer can be deleted — see polish list).

8. **M17: pendingFormat reset.** In `StepUpModal`'s `onCancel` callback (passed from ExportMenu), call `setPendingFormat(null)`. At top of `download`, set `setPendingFormat(fmt)` before fetch; reset in catch/finally regardless of path.

9. **M18: Retry on list error.**
   - Refactor `useAuditList` in `useAuditQuery.ts` to expose `retry: () => void`. Implementation: keep an internal `nonce: number` state, include in deps; `retry()` increments nonce.
   - In `AuditPage.tsx:30-34`, render a `<Button variant="ghost" onClick={list.retry}>{t("audit.error.retry")}</Button>` next to the error message.

10. **M10: Hook hardening.**
    - In `useAuditQuery.ts:18`, validate response: `if (!body || typeof body.total !== "number" || !Array.isArray(body.items)) throw new Error("Invalid audit response shape");`
    - In `useAuditQuery.ts:21-23`, guard error type: `.catch((err: unknown) => { if (err instanceof Error && err.name === "AbortError") return; setError(err instanceof Error ? err.message : String(err)); })`.

11. **M19: Clipboard / blob error handling.** In `AuditPanel.tsx:64,68,72,76`:
    ```ts
    const copyLink = async () => {
      try { await navigator.clipboard.writeText(url); toast.success(t("audit.panel.linkCopied")); }
      catch { toast.error(t("audit.panel.copyFailed")); }
    };
    ```
    Same pattern for `copyData` and Blob export. Wire toast keys (already added in S03 — if not, add them now).

12. **M9: Runtime shape guards.**
    - `AuditPanel.tsx:117-125`: replace `(metadata.scopes as string[]) ?? []` with `Array.isArray(metadata?.scopes) ? metadata.scopes.filter(s => typeof s === "string") : []`.
    - `AuditPanelModules.tsx:43`: after `Array.isArray(...)`, guard each item: `.filter((f): f is { field: string; from: unknown; to: unknown } => typeof f === "object" && f !== null && typeof (f as any).field === "string")`.

13. **M8: Drop non-null assertions.**
    - `AuditPanelHelpers.tsx:107,126,184`: at the top of each click-handler-bearing component, destructure: `const { target_type, target_id } = event; if (!target_type || !target_id) return null;` then use without `!`.
    - `AuditPanelModules.tsx:74`: refactor `LookupResult` discriminated union so `key` is `string` when `fallback === false`. Then drop `t(result.key!)`.

14. **M6: Calendar from/to swap.** In `AuditCalendar.tsx:23-32` (the day-click handler that finalizes the range):
    ```ts
    const finalize = (a: Date, b: Date) => {
      const [from, to] = a <= b ? [a, b] : [b, a];
      onChange({ from, to });
    };
    ```

15. **M11 (state-reset half): StepUpModal cleanup.** Add:
    ```ts
    useEffect(() => {
      if (open) { setCode(""); setRecoveryCode(""); setError(""); }
    }, [open]);
    ```
    Confirm the existing `if (!open) return null` does not unmount; the reset is necessary because state survives the null-render.

16. **Tests.**
    - Add `useUrlState.test.ts`: round-trip parse/stringify; reject `?view=hax` → fall back to default; reject `?outcome=xyz`.
    - Add `useAuditQuery.test.ts`: abort cancellation; retry nonce bump; invalid response shape rejection.
    - `AuditFilterBar.test.tsx:25-32`: fix the assertion to actually click "Clear all" (not just first chip) and assert the full payload shape including `outcome: undefined` and `q: undefined`.
    - `ExportMenu.test.tsx`: add a case for non-401 error → toast fires + button re-enables.
    - `AuditPanel.test.tsx`: add `selectedEventId` deep-link test.

## Acceptance criteria

```bash
cd web
npm run lint
npx tsc -b
npm run test -- --run
```

Manual:
- Paste `?event=<id>` URL → panel opens.
- Open then close panel → URL no longer has `?event=`.
- Pickers show skeleton during fetch (skeleton component arrives in S05; loading boolean must be exposed by S04 hook).
- Export with backend forced to 500 → toast appears, button re-enables.
- Click export format twice rapidly → only one fetch fires (DevTools Network).
- Open StepUp via Export, type a code, cancel, re-open → input is empty.
- Click date pair end-before-start → URL gets correct order.
- Paste `?view=garbage` → app loads with default view.

## Commit shape

```
fix(audit-fe): S04 — URL validation, hook hardening, picker dedup, export error/dedupe, retry
```

Two commits acceptable: one for hooks/state (B8 + M1 + M3 + M10 + M12 + M13), one for components (B6 + M2 + M6 + M8 + M9 + M11 + M17 + M18 + M19).
