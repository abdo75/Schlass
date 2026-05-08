# Audit-log frontend — frozen findings snapshot

Source: 3-agent review (standards / UI-UX / architecture) on `feat/audit-log` at `cb4657b`. IDs referenced from session briefs.

## 🔴 Blockers

- **B1** — `web/src/index.css:162-516` (panel CSS, ~360 LOC) — zero `.dark` overrides, hardcoded `oklch(...)` literals throughout. Panel illegible in dark mode. Replace literals with `var(--color-*)` tokens; add `.dark` overrides where necessary.
- **B2** — `AuditTimeline.tsx:108,139,144` — `bg-amber-100`/`text-amber-900`/`bg-amber-600` literal Tailwind palette bypasses design system; no dark variant. `--warning`/`--warning-border`/`--warning-foreground` token trio already exists in `index.css:73-75`. Use `bg-warning text-warning-foreground` + `bg-[--warning-border]` for dot.
- **B3** — `i18n/locales/{fr,de}.json` — 25 keys present in `en.json` missing in fr/de:
  - `audit.error.fetch`, `audit.error.retry`
  - `audit.eventLabel.auth.permission_denied`
  - `audit.eventLabel.config.*` (16 keys)
  - `audit.panel.system`
  - `audit.refine.actorOpener`, `refine.targetOpener`, `refine.eventTypeOpener`, `refine.label`, `refine.clear`
- **B4** — Hardcoded English strings (~40+ across these files):
  - `AuditTimeline.tsx:23,31-34,108,109` — `"No audit events found."`, `"Outcome"`, `"When"`, `"Activity"`, `"Actor"`, `"GDPR-erased"`, `"Critical"`, `"System"`
  - `AuditTabs.tsx:3-8` — all tab labels
  - `AuditTimePicker.tsx:42-72` — `"Last hour"`, `"Last 24 hours"`, `"Custom range"`, `"Apply"`
  - `AuditCalendar.tsx:11-12,48,53,191,199` — month names, `aria-label="Previous"/"Next"`, `aria-label="Pick ..."`
  - `AuditFilterBar.tsx:107,142,235,258,267-278` — `"selected"`, `"Click to clear"`, `"Click to edit selection"`, all preset labels, `"Actor:"`, `"Target:"`
  - `EventTypePicker.tsx:83,88-89` — `"{{count}} selected"`, `"Clear"`, `"Apply"`
  - `ActorPicker.tsx:35,41,51` — `"Search actors"`, `"System"`, `"No actors found."`
  - `TargetPicker.tsx:7-11,46,56,63,79` — `TYPE_LABELS` map, `"Back"`, `"Search targets"`, `"No targets found."`, `aria-label="Target type"`
  - `ExportMenu.tsx:10-14,70,90` — `FORMAT_LABELS`, `"Export"`, `"Bundle includes manifest.json with chain proof"`
  - `AuditPanelModules.tsx:40,115,151,142-153,164` — `"Changed fields"`, `"rows exported"`, `"Reset tokens"`, `"Auth codes"`, `"Rows updated"`, `"Redirect URIs"`, `"Scopes"`, `"Grants"`, `"Rows"`, `"Name"`, `"Value"`
  - `AuditPanelHelpers.tsx:222-243` — `humanizeTargetType` map (`"Client"`, `"Setting"`, etc.)
  - `AuditPanel.tsx:41,64` — `aria-label="Close"`, `aria-label="Event detail"`, `Copy link` URL pattern
  - `AuditLogTab.tsx:19-23,27,40,47` — settings strings
  - `AuditPage.tsx:36-37` — `"Loading..."`
- **B5** — `AuditPanel.tsx:38-56` + `StepUpModal.tsx:44-90` — `role="dialog"` lacks `aria-modal="true"`; no focus trap; no focus restoration; no autoFocus. Tab walks out of dialog. Pattern exists in `web/src/components/ConfirmDialog.tsx:30,45+`.
- **B6** — `ExportMenu.tsx:31-58,81` — `void download(fmt)` — non-STEPUP errors throw into the void with no UI; no double-submit guard; no progress feedback during seconds-long server-side export.
- **B7** — `AuditPage.tsx:35-38` — bare `"Loading..."` literal. Project has `web/src/components/PageSkeleton.tsx` with `schlass-shimmer` and `UsersTableSkeleton` matching this exact table shape.
- **B8** — `useUrlState.ts:8,15` — `params.get("view") as AuditState["view"]` and `outcome` cast unvalidated query strings to enum types. Validate against allowed sets, fallback to default.

## 🟠 Major

- **M1** — `useUrlState.ts:19,36` + `types.ts:61` + `AuditPage.tsx:18` — `selectedEventId` parsed/written but never opens panel (page uses separate `useState<AuditItem | null>`). Copy-link affordance is broken. Either wire (after `list.data` loads, find item + `setSelected`) or remove field.
- **M2** — `AuditTimeline.tsx:134` vs `AuditPanelHelpers.tsx:5` — `OutcomeChip` defined twice with incompatible prop APIs (`onClick: MouseEventHandler` vs `onFilter: (Outcome) => void`). Single canonical chip; delete dupe.
- **M3** — `ActorPicker.tsx:9-21`, `TargetPicker.tsx:24-36` — no loading state (empty list shows `"No actors found."` while fetching); error and empty visually identical; re-fetches on every page change because `state` is full effect dep. Extract `usePickerFetch<T>` with stable-key + error tracking.
- **M4** — `AuditTimeline.tsx:76-103` — whole `<tr>` is `onClick`+`cursor-pointer` but no `role="button"`/`tabindex`/keydown. Keyboard users locked out. Also nested buttons inside clickable row = invalid interactive nesting.
- **M5** — `AuditCalendar.tsx:11-12,58,60-75` — hardcoded English month names + `["M","T","W"…]` weekday strip; no `Intl.DateTimeFormat`; no arrow-key day nav (←→ day, ↑↓ week, PgUp/PgDn month).
- **M6** — `AuditCalendar.tsx:23-32` — no swap when `from > to`; URL gets `since>until`, API returns nothing.
- **M7** — `AuditTabs.tsx:12-26` vs `SettingsPage.tsx:269-285` — pill style vs underline style for the same widget across the app. Pick underline. ARIA tab pattern incomplete (no `aria-controls`, no roving tabindex, no arrow nav).
- **M8** — `AuditPanelHelpers.tsx:107,126,184` + `AuditPanelModules.tsx:74` — non-null assertions (`!`) inside `onClick` after render guards. Refactor to local consts + early return.
- **M9** — `AuditPanel.tsx:117-125` + `AuditPanelModules.tsx:43` — unsafe casts (`(metadata.scopes as string[]) ?? []`, `f as { field: string … }`) without runtime shape validation.
- **M10** — `useAuditQuery.ts:18,21-23` — no response shape validation; `err.name` access on non-Error rejection.
- **M11** — `StepUpModal.tsx:13-20,33-37,73-81` — state persists across opens (TOTP pre-filled on next step-up); generic `audit.stepup.too_old` for any non-`ApiRequestError` (network drop labeled "MFA failed"); recovery toggle in tab order between input and Submit; no autoFocus; no ESC handler.
- **M12** — `AuditFilterBar.tsx:27-40` — boot-from-URL hydration `useEffect` deps on full `state` (memoized fresh ref every render); duplicates `TargetPicker.tsx:24-36` fetch; doesn't match `target_type` (id-collision risk).
- **M13** — `AuditFilterBar.tsx:223,237,259` — three near-identical pill components (`Opener`, `ActiveChip`, `ActiveOpener`) duplicate styles. Single `<Pill variant>`.
- **M14** — `EventTypePicker.tsx`, `AuditTimePicker.tsx` popovers — no `role="menu"`/`role="dialog"`, no Enter-to-Apply, no ESC inside picker, no `aria-haspopup`/`aria-controls` from openers. Hardcoded `w-[28rem]` overflows mobile.
- **M15** — `index.css:200,216,223` + 3 modal backdrop recipes (`bg-black/35` vs `bg-foreground/35 backdrop-blur-sm` vs panel CSS literal `oklch(...)`) — pick one, codify as utility/component.
- **M16** — `index.css` panel CSS classes (`.panel-close`, `.panel-btn`, `.panel-fact-link`) — no `focus-visible:ring-3 focus-visible:ring-ring/50`. Standard rest-of-app focus indicator missing.
- **M17** — `ExportMenu.tsx:33-58` — `pendingFormat` not reset on Cancel→re-open; stale state.
- **M18** — `AuditPage.tsx:30-34` + `useAuditQuery.ts` — error has no Retry button despite `audit.error.retry` key existing; hook doesn't expose `retry()`.
- **M19** — `AuditPanel.tsx:64,68,72,76` — `void navigator.clipboard?.writeText(...)` and Blob export silently swallow rejections.
- **M20** — `AuditPanel.tsx:39-56` + `index.css:162-516` — 360-LOC bespoke panel CSS reinvents drawer/modal primitives (`ConfirmDialog`, sonner already exist). Two divergent design systems.

## 🟡 Polish

- `AuditPanel.tsx:41` close button uses `×` glyph; rest of app uses `<XIcon>` from `lucide-react` (own `StepUpModal.tsx:52` uses XIcon).
- `AuditTimeline.tsx` `formatRelative()` hand-rolled, English-only; `AuditPanelHelpers.tsx:relativeTime` uses `Intl.RelativeTimeFormat` correctly. Dedup.
- `AuditFilterBar.tsx:267-278` `presetLabel()` duplicates `AuditTimePicker.tsx` PRESETS array.
- `AuditPanelModules.tsx:110-119` `ExportSummary` — hardcoded English + `panel-count-value` for label (likely should be `panel-count-label`).
- `ExportMenu.tsx:24-29` filename omits format hint.
- `ExportMenu.tsx:88-92` `lastManifest` flag persists as permanent footer instead of one-shot toast.
- `AuditFilterBar.test.tsx:25-32` "Clear all" assertion hits first chip click, missing `outcome`/`q` keys.
- Missing tests: `useUrlState.ts`, `useAuditQuery.ts`, `AuditTabs.tsx`, picker error/loading states.
- `AuditPanel.test.tsx.snap` snapshots too narrow (5 thin cells).
- `EventTypePicker.tsx:11-19` wasted `useMemo` for state initializer (use lazy `useState(() => …)`).
- `eslint.config.js` test override disables 4 `no-unsafe-*` rules globally — too broad.
- `catalog.ts:86` `severity()` unused `_metadata` param.
- Microcopy: `"GDPR-erased"` jargon → "Former user (GDPR)"; `"Bundle includes manifest.json with chain proof"` → "Includes signed integrity manifest"; passive `audit.error.fetch` → action-oriented.
- `AuditPage.tsx:36-37` `"Loading..."` ellipsis style mismatches rest-of-app `Loading…` (single char).
