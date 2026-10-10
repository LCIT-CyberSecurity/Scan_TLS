# Notifications

Connectors (*Administration → Settings*; secrets only from the environment, never the database):

| Connector | Settings in the UI | Secret |
|---|---|---|
| **SMTP** | host, port, STARTTLS (certificate verified), username, sender | `TLS_SCAN_SMTP_PASSWORD[_FILE]` |
| **Microsoft Graph** (`sendMail`, client-credentials) | tenant id, client id, sender mailbox | `TLS_SCAN_GRAPH_CLIENT_SECRET[_FILE]`; application permission `Mail.Send` with admin consent |

*Test connection* walks through the connector with a readable explanation per step: SMTP = DNS → TLS/authentication →
send (e.g. "TLS certificate not trusted", "authentication refused"); Graph = token (`invalid_client`, tenant/client/secret
hints) → send (403 → "grant Mail.Send"). No secret is ever displayed or logged.

Events (per-user opt-in in *Preferences*, all on by default):

| Event | When | Recipients |
|---|---|---|
| scan completed / failed / cancelled | end of every run (expired counts as failed) | everyone who requested the run (initiator, schedule owner, users attached by de-duplication) |
| certificate expired or expiring | a completed run has endpoints whose certificate expires within the profile's `expires_within_days` (per endpoint) | same |
| new non-compliance | the run has findings on endpoints that were not affected in the previous comparable run | same |
| schedule problem | an occurrence was missed (service down) or could not start (e.g. policy has no published version) | the schedule's owner |

Content: status, key figures, the main items and a **link** to the run in the WebUI. **No report is attached.**
Delivery is asynchronous (table `notifications`; failures keep a readable error: *Administration → notifications* API).
With no connector configured, notifications are marked *skipped*.

Tested: SMTP (sink server), Graph (mock server only — **not** against a real tenant), every event above.
