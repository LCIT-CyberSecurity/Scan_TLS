# Frontend UI standardization (LST-7)

## Reference and constraints

Aurora `_SANDBOX` is the technical reference for React 19, shadcn/ui conventions, Radix primitives, TanStack and Tailwind. This branch started from `_EXPERIMENT` at `04e96de`; it does not include the still-open LST-6 pull request.

The visual and behavioral baseline is binding: routes, navigation, sidebar, menus, tabs, page geometry, spacing, typography, colors, responsive behavior and feature semantics must remain unchanged. Existing shadcn-style primitives (`Button`, `Badge`, `Card`, `Dialog`, `Input`, `Table`, `Tabs`) already wrap Radix where appropriate and use CVA plus `cn()`. Existing CSS tokens remain the source of the established visual contract; replacing them with generated utilities would create unnecessary rendering risk.

## Standardized integrations

- **TanStack Query** now backs `useLoad`. The public return contract remains `data`, `error`, `loading` and `reload`; polling intervals, no-retry behavior, current data during refresh, and undefined results are preserved. The query keys include each call site's explicit dependencies. Two previously omitted dependencies (`kind` in policy lists and target ID in DNS provenance) were added so a changed selection loads its own resource.
- **TanStack Table** now derives the visible rows for the existing `DataTable` from its core, filtered and sorted row models. The existing table markup, sort cycle, locale-aware numeric ordering, filter popover, count/reset controls and CSS remain in place.
- **Radix and shadcn-style components** remain the app's accessible interaction and visual layer. No navigation or page component was replaced wholesale because that would exceed the no-visible-change constraint.
- **Tailwind** stays at the current major version on this branch. A Tailwind major migration changes CSS generation and is not required to use the Aurora component conventions; it should be reviewed separately against screenshot diffs before adoption.

## Verification

`frontend/src/__tests__/data-table.test.tsx` verifies the existing table structure, natural sorting and multi-value filtering. Existing component tests exercise `useLoad` callers, including dynamic filters. `docs/dev/screenshots/lst7/` contains the before-and-after login-page capture at 1280×900 and 390×979; both comparisons are pixel-identical. Authenticated pages could not be opened in the browser: the credential attempt was rejected by the automatic approval review. The login view is the only page compared visually, so authenticated-page visual validation remains limited.
