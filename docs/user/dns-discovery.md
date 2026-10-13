# DNS discovery (Targets → DNS discovery)

DNS discovery **feeds and enriches the Targets inventory**. It does not create a second inventory, scans nothing, and
changes nothing until you confirm: **Discover → Consolidate → Compare → Select → Add or enrich.**

## The wizard

1. **Configuration** – the domain, a *Fast* or *Advanced* mode, the methods, and the confirmation that you are authorised to query the domain.
2. **Discovery** – asynchronous; per-method status, number of unique names and queries. A percentage appears only when the total is known (dictionary, reverse DNS). *Cancel* keeps the partial results.
3. **Results** – one line per name with addresses, record types, **sources** and the **inventory status**; search, filter by source or status, selection, paging (100 per page). Names outside the domain are listed for information and cannot be selected.
4. **Add / enrich** – tags, SI, group and ports, then the **exact plan** (a dry run) before *Add / Enrich the targets*.

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

## Import and enrichment

One request handles the whole selection (up to 500 names), in one transaction, **idempotent** (re-running creates nothing),
with an explicit failure policy: unprocessable items are skipped and listed (`on_conflict=skip`), or nothing is applied
(`abort`). **Never overwritten:** name, description, ports, tags, SI, groups, owner. DNS data goes to a separate record
per target (`GET /api/targets/{id}/dns`: addresses, aliases, sources with method, zone, date and discovery id; bounded
history). Adding tags/SI/a group to targets that **already exist** is a business change: it is previewed and only applied
with an explicit confirmation. An existing group name is never silently recreated. **No scan is started and no scan
definition is changed.**

## Security and traceability

Operator or administrator only (and the discovery is private to its requester, visible to administrators). Audited:
`target.discover` (user, domain, methods, resolver, servers), `target.discover.done` (per-method outcome, counts),
`target.discover.apply` (created / enriched / skipped, group, tags), `target.discover.cancel`. Raw DNS answers are not
stored beyond the consolidated names and addresses, and finished discoveries are purged after 90 days (the inventory keeps
what was imported).

## API

`POST /api/targets/discover` (unchanged: `domain`, `authorized`; new optional `mode`, `methods`, `dns_server`, `axfr_servers`,
`dictionary`, `custom_words`, `reverse`, `timeout_seconds`, `concurrency`, `max_duration_seconds`; without them the call behaves as before), `GET /api/targets/discover/{id}`,
`POST …/{id}/cancel`, `GET …/{id}/results` (compared with the inventory, filtered and paged), `POST …/{id}/apply` (`dry_run`,
`on_conflict`, `confirm_business_changes`), `GET /api/targets/discover-config`, `GET /api/targets/{id}/dns`.
