# Audit-log frontend fixup — session plan

## Context

Branch `feat/audit-log` (M0–M10 done, at `cb4657b`, pushed). Pre-squash-merge frontend audit found theming, a11y, i18n, correctness, and polish gaps. Work split into 5 sequential sessions so each fits one fresh Claude context without prior-session reread.

**No PRs.** All work commits onto `feat/audit-log`. Squash to `main` happens after Session 5.

## Ordering & dependencies

Sessions are sequential — each depends on the previous landing first to avoid file-conflict re-work:

| # | Session | Primary surfaces | Why this order |
|---|---------|------------------|----------------|
| 01 | Theming + design-system | `index.css`, `AuditTabs.tsx`, `AuditTimeline.tsx` chips | CSS first — later sessions add ARIA/i18n/state on top of stable visuals |
| 02 | A11y patterns | `AuditPanel.tsx`, `StepUpModal.tsx`, `AuditCalendar.tsx`, pickers | Adds ARIA/keyboard atop S1 styling; S3 will translate aria-labels |
| 03 | i18n full extraction | every audit `.tsx`, `i18n/locales/{en,fr,de}.json` | Mechanical — must follow S2 so new aria-labels go in too |
| 04 | Correctness + state + data | `useUrlState.ts`, `useAuditQuery.ts`, `ExportMenu.tsx`, pickers, `AuditPanel.tsx` clipboard | Logic refactor — independent of styling but disturbs same files; safer last-but-one |
| 05 | Loading states, tests, polish | new `AuditTableSkeleton.tsx`, picker skeletons, missing hook tests, microcopy, dedupes | Wires skeletons + retry to refactored hooks from S4 |

## Branch state at session start

Each session begins with:

```bash
git checkout feat/audit-log
git pull --ff-only origin feat/audit-log
git status   # must be clean
```

Each session ends with one or more commits pushed to `feat/audit-log`. Commit messages follow conventional-commit form already established on the branch:

```
fix(audit-fe): <session-id> — <short summary>
```

## Verification cadence

Every session must end with **all** of these green:

```bash
cd web
npm run lint
npx tsc -b
npm run test -- --run         # vitest
npx playwright test --grep audit  # only if e2e changed
```

Plus session-specific acceptance criteria in each brief.

## Memory pointer

Update `MEMORY.md` after each session lands. Entry name: `project_audit_fe_fixup_progress.md`. Format: `S0X done at <commit>; next = S0Y`.

## Out of scope

- Backend audit code (already shipped + tested in M0–M10).
- New audit features beyond what's already on the branch.
- Migration squash (handled separately post-merge).
- E2E test additions beyond regressions caught by existing `audit-viewer.spec.ts`.

## Source-of-truth findings

Full punch-list lives in this repo at `docs/plans/audit-frontend-fixup/findings.md` (frozen snapshot from pre-fixup review). Each session brief references its findings IDs.
