# DNS discovery (Targets → DNS discovery)

DNS discovery **feeds and enriches the Targets inventory**. It does not create a second inventory, scans nothing, and
changes nothing until you confirm: **Discover → Consolidate → Compare → Select → Add or enrich.**

## History: Targets → DNS discoveries

The **DNS discoveries** tab (next to Groups) lists your discoveries (all of them for an administrator): domain, date, status, number of names, methods and their outcome. *Open* shows the results again, so you can select **all, some, or only the new names** and import or enrich later; *Delete* forgets a finished discovery (the targets already imported are not affected). Finished discoveries are purged after 90 days.

## The wizard

1. **Configuration** – the domain, a *Fast* or *Advanced* mode, the methods, and the confirmation that you are authorised to query the domain.
2. **Discovery** – asynchronous; per-method status, number of unique names and queries. A percentage appears only when the total is known (dictionary, reverse DNS). *Cancel* keeps the partial results.
3. **Results** – one line per name with addresses, record types, **sources** and the **inventory status**; search, filter by source or status, selection, paging (100 per page). Names outside the domain are listed for information and cannot be selected.
4. **Add / enrich** – tags, SI, group and ports, then the **exact plan** (a dry run) before *Add / Enrich the targets*.

## From the discovery to Targets, in a few clicks

**Targets → DNS discovery → Results → Add → See the imported targets.**

1. The results open with a summary: hosts discovered, new, existing, to enrich, outside the domain.
2. **Add the new targets** selects every new name of the domain (never the names outside it, the wildcard answers, the
   historical names that no longer resolve, nor the names already scanned unless you tick *Also include…*) and goes to the
   import step. **Add / Enrich the selection** does the same for a hand-made selection.
3. The import step proposes, and shows the exact plan (dry run) before anything is written:
   - the tag **Découverte DNS** (on by default, can be turned off);
   - the group **DNS — your-domain** (no date in the name: it is created the first time, then fed again by each later
     discovery of the same domain; you can pick another group, create another one, or use none);
   - optional SI / sub-SI, extra tags and ports (existing ports are kept);
   - **Advanced options — Scans** (folded): add the group to existing scans or create a scan. Nothing is ever launched.
4. The summary lists what will be created, enriched, already known (left unchanged), the group and the tag. When the
   import changes the tags, group or SI of targets that **already exist**, one confirmation box covers all of them.
5. After the import, **See the imported targets** opens Targets filtered on exactly the targets this import processed
   (created, enriched or reused), with **Back to the full list** to leave the filter.

**Tag and provenance.** The tag is a practical filter, not the proof of origin: that is the DNS record kept for each target
(method, domain, dates, addresses, aliases, discovery). New targets get the tag; a target that already exists only gets it
after your confirmation, and tags are never removed. In the Targets list the **Origin** filter shows every target a
discovery has seen, and the **DNS** badge (green = created by a discovery, grey = enriched by one) opens the source domain,
methods, first and last observation, addresses and aliases. A DNS name does not prove that the host is reachable or serves
TLS: only a scan tells. Manually created targets are unchanged and show nothing extra.

## Methods (independent, each can fail without affecting the others)

| Method | What it does |
|---|---|
| DNS records | Apex A/AAAA/SOA/NS/MX/TXT and common SRV records. NS, MX and SRV targets are kept with their role; targets outside the domain are flagged, never followed. TXT is informational only, never a target. |
| Zone transfer (AXFR) | Asked of the domain's authoritative servers **and** of the servers you tick (Advanced). One report per server. A refusal is the normal answer. Bounded in records, size and time. An open transfer on a *public* authoritative server is reported as a DNS security observation, never as a TLS result. |
| Dictionary | A short embedded list (fast), an extended list or your own (max 5 000 labels). A random label is tested first: **wildcard** answers are detected and the names that only resolve to the wildcard address are dropped. |
| Certificate Transparency | Public domains only, and only if the administrator allows it. Names are filtered to the domain and resolved; a name found in a certificate that does not resolve is marked *historical*, never *active*. Two providers (crt.sh, then certspotter) – an outage never fails the discovery. **An internal domain (`.local`, `.lan`, `.corp`, `.internal`, `.test`, …) is never sent to any external service.** |
| Reverse DNS | PTR of IP addresses or small networks (256 addresses max). The forward A/AAAA is checked and a mismatch is flagged. A PTR never widens the perimeter. |

## Internal DNS servers and split DNS

By default the worker's resolver is used. To query an internal DNS server (or to attempt AXFR against it), an
**administrator declares it first**: *Administration → Settings → DNS discovery* (one IP per line, optional `:port`). A
discovery can only point at declared servers; loopback, link-local, multicast, reserved and cloud-metadata addresses are
always refused, a server is always an IP address (never a name that could be rebound), and CT redirects are not followed.

## Comparing with the inventory

| Status | Meaning | Possible action |
|---|---|---|
| NEW | The FQDN is not in the inventory. | Add |
| EXISTING | It is, and DNS brings nothing new. | Keep |
| ENRICHABLE | It is, and DNS observed a new address, alias or source. | Enrich |
| CHANGED | The addresses/alias differ from a previous observation (an address not seen this time is **kept**, never deleted, and never read as "the host is gone"). | Enrich |
| OUT OF SCOPE | Name outside the domain (MX, NS, CNAME, PTR, CT…). | Never imported implicitly |

Matching uses the Targets normalisation. The inventory identity stays `(value, ports)`: when the FQDN exists with
**other ports**, no `ports=""` duplicate is created – the item is reported (*exists with other ports*), and when
several targets carry the name you **choose which one** to enrich. Several FQDNs sharing an IP stay separate targets.

## Already scanned? (avoiding double scanning)

Each name carries a **coverage** column in the results, computed read-only:

- **Covered**: a scan definition scans it, either as a direct target, through a group, or through an IP / network target
  that contains an address the name resolves to ("via 10.10.0.0/28"). A scheduled definition is flagged *scheduled*.
- **Recently scanned**: a completed run of the last *N* days scanned that name or address (Administration → Settings →
  DNS discovery → *Recent scan (days)*, 7 by default, 1 to 365).
- *Same address as …*: the name resolves into a scanned address or network (several names, one access point).

Names that are covered or recently scanned are **unchecked by default** in "Select all", "Select the new ones" and
"Select the enrichable ones"; tick *Also include the names already covered* to include them, or tick a row by hand at any time.

## From the discovery to a scan

In the last step, the **Scan** section turns the import into something scannable, in the same transaction:

- *Add the group to existing scans*: the group (existing, or created with the default name `Discovery <domain> <date>`) is
  added to the chosen definitions. Nothing already in the definition is removed. A scheduled definition will scan the new
  names at its next run (the plan says so).
- *Create a new scan on this group*: a definition (profile, policies, optional exclusions through the API) is created on
  the group. Using a group rather than listing targets means later discoveries that feed the group are picked up
  without touching the definition.

A scan scans a group, so choosing a scan always creates or uses a group. Targets that already exist only join the group
once the business change is confirmed. **No scan is launched**: you start it from Scans.

## Import and enrichment

One request handles the whole selection (up to 500 names), in one transaction, **idempotent** (re-running creates nothing),
with an explicit failure policy: unprocessable items are skipped and listed (`on_conflict=skip`), or nothing is applied
(`abort`). **Never overwritten:** name, description, ports, tags, SI, groups, owner. DNS data goes to a separate record
per target (`GET /api/targets/{id}/dns`: addresses, aliases, sources with method, zone, date and discovery id; bounded
history). Adding tags/SI/a group to targets that **already exist** is a business change: it is previewed and only applied
with an explicit confirmation. An existing group name is never silently recreated. **No scan is started**, and a scan
definition is only touched when you ask for it (see above): its group list gains the group, nothing is removed.

## Security and traceability

Operator or administrator only (and the discovery is private to its requester, visible to administrators). Audited:
`target.discover` (user, domain, methods, resolver, servers), `target.discover.done` (per-method outcome, counts),
`target.discover.apply` (created / enriched / skipped, group, tags), `target.discover.cancel`. Raw DNS answers are not
stored beyond the consolidated names and addresses, and finished discoveries are purged after 90 days (the inventory keeps
what was imported).

## API

`POST /api/targets/discover` (unchanged: `domain`, `authorized`; new optional `mode`, `methods`, `dns_server`, `axfr_servers`,
`dictionary`, `custom_words`, `reverse`, `timeout_seconds`, `concurrency`, `max_duration_seconds`; without them the call behaves as before), `GET /api/targets/discover/{id}`,
`POST …/{id}/cancel`, `GET …/{id}/results` (compared with the inventory and with the scans: `coverage` per name, filtered and paged), `POST …/{id}/apply` (`dry_run`,
`on_conflict`, `confirm_business_changes`, `discovery_tag`, `reuse_group`, `scan_definition_ids`, `new_definition`: `name`, `profile_id`, `policy_ids`, `report_template_id`, `exclusions`), `GET /api/targets/discover` (history), `DELETE /api/targets/discover/{id}`, `GET /api/targets/discover-config`, `GET /api/targets/{id}/dns`.
