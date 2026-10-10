# Notifications

* Connector: **SMTP** (host, port, STARTTLS or implicit TLS, username, sender in *Administration → Settings*; the
  password comes from `TLS_SCAN_SMTP_PASSWORD[_FILE]`, never stored in the database). STARTTLS verifies the
  server certificate.
* Events (per-user opt-in in *Preferences*; default on): scan completed (incl. partial), scan failed/expired,
  scan cancelled. Recipients: everyone who requested the run (initiator, schedule owner, users attached by
  de-duplication).
* Content: status, key figures and a link to the run in the WebUI. **No report attachment.**
* Delivery is asynchronous (queue in `notifications`); failures are kept with a readable error
  (*Administration → notifications* API). With no connector configured, notifications are marked *skipped*.
* *Test connection* walks DNS → TLS/auth → send with an explanation per step.
* Not implemented: Microsoft Graph sender, "new non-compliance", "certificate near expiry" and "schedule problem"
  e-mails (the events are reserved in the preferences API; see [limitations](../limitations.md)).
