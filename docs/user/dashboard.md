# Dashboard: indicators and how they are computed

The dashboard reads persisted results only (run summaries, endpoints, findings). Nothing is re-evaluated and no historical result is changed. The filters (my scans / all scans, information system, tag) apply to every block; "all scans" is reserved to operators and above.

**Basis.** The latest finished run (completed or partial) of every scan definition in the filter. An endpoint is identified by hostname + address + port and counted once, from the most recent of those runs; the same address behind two different names stays two endpoints. Failed, cancelled and expired runs never feed the picture.

| Indicator | Definition |
|---|---|
| TLS compliance | compliant ÷ (compliant + non-compliant) on distinct endpoints. Endpoints in error or not tested are shown apart ("not evaluated") and never counted as compliant. When nothing could be evaluated the card says "Not evaluated": there is no 0 % or 100 % by default. |
| Non-compliant endpoints | Distinct non-compliant endpoints of the basis. |
| Critical and high findings | Distinct findings (one per type of problem) of those severities, with the number of distinct endpoints in the tooltip as "occurrences". Informational findings and scan errors are not counted. Complementary TLS checks are never counted here. |
| Certificates to watch | One per certificate fingerprint. Expired, or expiring within 30 days. Remaining days are the ones measured by the scan minus the days elapsed since. |
| Compliance breakdown | Compliant / non-compliant / not evaluated or partial, with numbers and percentages. A warning appears when the basis mixes several policies or policy versions. |
| Compliance over time | Compliance rate of the successive runs of **one** scan definition (selector when several exist), 20 runs at most. A run with nothing evaluated leaves a gap. A hollow point means the scope, profile, checks or policy version changed since the previous run: the evolution is then not a pure security trend. |
| Evolution between two dates | For the scan definition of "Compliance over time", between a **From** and a **To** date (the last 30 days by default). Reference scans: the latest finished scan on or before each date; when nothing exists before the first date, the earliest scan of the window. Shows new / fixed / persistent / not-retested findings (a service not tested again is never reported as fixed), occurrences per severity at both ends with the change, the main new and fixed findings, endpoints added and removed, compliance improvements and degradations, certificate changes, and the findings of every scan in between as a stacked bar chart. A caution is shown when the targets, profile, policy versions or completeness differ between the two scans. *Open the detailed comparison* opens the full comparison of those two scans. |
| Priority watch points | At most six anomalies actually present: findings by severity then number of endpoints, then complementary checks that ended in FAIL. Disabled, not tested, not applicable or inconclusive checks are never listed. |

API: `GET /api/dashboard` keeps its previous fields and adds `posture`, `trend` (optional `trend_definition` parameter) and `evolution` (optional `evolution_from` / `evolution_to` dates, `YYYY-MM-DD`; `status` is `ok`, `single_run`, `no_runs` or `invalid_range`). Aggregation code: `services/evolution.py`. Aggregation code: `backend/src/tls_scan_app/services/dashboard.py`.
