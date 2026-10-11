# UI parity with LCIT-Sign (and EARE for dense technical screens)

Scope: the authenticated web UI only. No engine, API, model, permission, worker, scheduler or Standalone change.

## Method

LCIT-Sign's stylesheet (`frontend/src/styles.css`, cascade resolved: later "EARE look" and "premium finish" overrides win) is the source of truth.
TLS Scan keeps React + Tailwind + Radix, but the look now lives in **one shared stylesheet** (`frontend/src/styles/components.css`) that uses
LCIT-Sign's class names and values (`.sidebar`, `.nav-link`, `.topbar`, `.card`, `.metric`, `.button--*`, `.badge`, `.simple-table`, `.modal`,
`.user-menu`, `.empty-state`…). The shared React components (`components/ui/*`, `components/common.tsx`) emit those classes, so pages are not
restyled one by one. Tailwind remains for layout utilities; its type scale is remapped to LCIT-Sign's sizes (12.5 / 13.5 / 14.5 / 16 px).

Tokens (`styles/tokens.css`) are LCIT-Sign's; this work added what was missing: Violet premium finish (canvas wash, `--shadow-card`),
Studio dark, and the Studio geometry.

## Correspondence matrix

| TLS Scan component | Reference | Change |
|---|---|---|
| Tokens, 5 styles × light/dark/system | LCIT-Sign | Added Violet finish, Studio dark, `--shadow-card`; Studio geometry in components.css |
| Body, typography | LCIT-Sign | 16/24 px Inter, `letter-spacing -0.006em`, font features, fixed canvas wash; Tailwind scale remapped |
| Sidebar, brand, nav, footer | LCIT-Sign | 264 px rail, section headings, 44 px links, active gradient + edge, "signed in as" footer |
| Topbar, breadcrumb | LCIT-Sign | 58 px blurred bar, `TLS Scan › section`, mobile menu button + scrim |
| User menu | LCIT-Sign | `details` menu: identity, light/dark/system, five style swatches, preferences, sign-out (persisted to the profile as before) |
| Card, KPI | LCIT-Sign / EARE | `.card` (flush header/body), `Metric` tile with icon chip and alert tone, hover only when it is a link |
| Button, Badge | LCIT-Sign | `.button--primary/secondary/ghost/danger`, 40/32 px; bordered 12 px badges with tone triplets |
| Table | EARE / LCIT-Sign | `.simple-table` in a card: sunken uppercase header, row hover, 14.5 px; horizontal scroll (min 720 px) on small screens |
| Input, Select, Textarea, Field | LCIT-Sign | Global field rule (8/10 px padding, strong border, radius-sm), label/hint scale |
| Dialog | LCIT-Sign | `.modal` on a blurred scrim, overlay shadow, entry animation |
| Tabs | LCIT-Sign | `.tabs` / `.tab` underline |
| Notes, empty, loading | LCIT-Sign | `Note`, `ErrorNote`, `Empty` (icon chip), `Loading` |
| PageHeader | LCIT-Sign | `.page-title` 26/34 with accent bar, subtitle, actions |

## External access screens (API and MCP)

Built from the same classes as the rest of the UI (`card`, `badge`, `note`, `button`, `modal`, tokens, light/dark and the five styles), following EARE's ergonomics:
* **Administration → Settings**: a card with one switch per service (External API, MCP server), each with its state badge and a note that both are off by default.
* **Administration → Users**: an *API* and an *MCP* column per user (individual authorisation, key prefix and *Revoke* when a key exists). Administrators cannot create or read a key.
* **Preferences → API and MCP access**: one card per service with the global state, the individual authorisation, the key state/expiry/last use, *Generate / Regenerate* (disabled with an explicit message when the service is off or the account is not authorised), *Revoke* and a *How to connect* snippet; a new key is shown once in a dedicated dialog with a *Copy* button and a warning.

## Deliberate differences

* The global focus ring uses the `--ring` token on every focusable element (LCIT-Sign relies on the browser default outside its login page).
* Studio compact geometry is applied to the shared classes, not to LCIT-Sign-specific ones (`.panel`, `.source-grid`).
* Business-specific pieces (TLS grades, severity badges, compliance bars) keep TLS Scan's markup, restyled with the same tokens.

## Validation

See the delivery report: screenshots of TLS Scan (CrashTest data) at 1440×900, 1024×768 and 390×844, all five styles, light and dark.
**Reference captures of LCIT-Sign and EARE after authentication were not taken**: their running instances require credentials that were not
available (and were not guessed). Parity is therefore established from the reference *code and tokens*, not from side-by-side screenshots.
