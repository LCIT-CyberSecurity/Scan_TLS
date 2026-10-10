# User guide (WebUI)

## Roles (global, not per SI)
| Role | Can |
|---|---|
| AUDITOR | see dashboard, runs, reports; download reports; filter by SI / sub-SI / tag. Nothing else. |
| USER | + create/manage **own** targets, groups, definitions, schedules; launch and cancel own scans; compare runs; consult policies/profiles |
| OPERATOR | + see/cancel/delete every scan, edit any definition/target/schedule, manage policies, profiles, report templates, SI and tags, see failed runs |
| ADMIN | + users and roles, settings (retention, SMTP), audit log, diagnostics |

Everyone signed in can read shared results; only an object's owner (or an operator) can modify it.

## Typical flow
1. **Targets & groupings** → *New target*: FQDN, IP or CIDR, optional ports (`443,8443,9000-9010`), description,
   tags, SI/sub-SI. Importing: one `value;ports;description` per line. A target exists once and can be used by any
   number of definitions and groups. SI, sub-SI and tags only help you organise and filter.
2. **Scans → Definitions → New scan**: pick targets/groups, a *technical profile* (how to scan), one or more
   *policies* (what is acceptable; the latest published version is used), a report template, tags and SI.
3. **Run**. The run page shows the current phase (*port discovery*, *TLS analysis*, *evaluating compliance*,
   *generating reports*), elapsed time and — only when reliable — hosts processed. No fake percentage.
4. **Cancel** your own scan any time: unstarted hosts are skipped and listed, results gathered so far are kept
   (*cancelled*, never counted as compliant).
5. **Results**: endpoints with grade/compliance/TLS versions/certificate, findings with evidence and
   remediation, errors, and *checks not performed* (never shown as compliant). Download HTML / Markdown / CSV / CBOM.
6. **Compare with previous**: new / fixed / persistent findings, TLS version, cipher suite and certificate changes.
   A target that was not re-tested is listed as *not re-tested*, **never as fixed**. Warnings tell you when the
   scope, profile or policy versions differ.
7. **Schedules**: once, daily, weekly, monthly, or cron (≥ 5 min). Scheduled scans use the latest published policy
   versions. See next run, last result, and the history (including skipped occurrences and why).

## Equivalent scans are shared
If someone already runs an identical scan (same effective targets/ports, profile, policy versions), your request
attaches to it — you will find the result in *My scans* and get the notification — without extra network load. You
gain no right to modify the other user's definitions or schedules. After it finishes, run again for fresh data.

## Preferences
Language (FR/EN/DE; browser language by default, your choice wins and is stored on your profile), light/dark/system,
palette, e-mail notification events, local password change.

## What "no TLS service" means
A target with no TLS on the scanned ports yields a *completed* run with zero endpoints and an explicit notice. It
is neither an execution error nor a compliance result.
