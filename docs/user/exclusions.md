# Exclusions: what a scan must never touch

An exclusion is an **IP address**, a **network** (CIDR), a **name** (FQDN) or a **wildcard name** (`*.test.example.org`: everything below, not the domain itself).
They apply to every way of starting a scan (manual, scheduled, API) because they are part of the immutable snapshot of the run.

## Where to set them

| Level | Where | Who | Applies to |
|---|---|---|---|
| **Global** | Administration → Settings → *Global exclusions* | ADMIN | every scan, whatever its definition or profile |
| **Scan definition** | Scans → Definitions → *Exclusions (never scanned)* | owner / OPERATOR | that definition (and its schedules) |
| **Profile** | `scan.exclude` in the profile content (API / YAML) | OPERATOR | every scan using that profile |

The three lists are merged. The run page shows what was applied (*N exclusion(s) applied*, with the scope of each entry, the targets that were not scanned and the networks that were narrowed).

## What happens

* A target covered entirely by an exclusion (an excluded IP or name, a network inside an excluded network, a name under an excluded wildcard) is **removed before the scan**. If nothing is left, the launch is refused (*every target is excluded*).
* A network that only **overlaps** an exclusion is kept and nmap skips the excluded addresses (`--exclude`): scanning `10.0.0.0/24` with `10.0.0.5` excluded scans the other 253 hosts.
* A **name** is never given to nmap, because it would exclude the address it resolves to and therefore every other name served at that address. Excluding `app.example.org` removes that target only; if another target reaches the same address, the address is still scanned through that one. To keep an address out of every scan, exclude the **address**.
* Hosts discovered during the scan are checked again: an address in an excluded network is dropped, and so is a host whose reverse name matches an excluded wildcard.
* Two scans that differ by an exclusion are different scans (they are never merged by the equivalence check).
* Existing definitions and profiles have no exclusion: nothing changes for them.

## Validation

Entries are validated as strictly as targets, because they reach nmap's command line: only addresses, networks and host names are accepted (no spaces, commas, options, or bare `*`/`*.com`); at most 500 entries.

## Standalone engine

```yaml
defaults:
  scan:
    ports: fast
    exclude: [10.0.0.5, 10.20.0.0/24, legacy.example.org, "*.test.example.org"]
```

or `tls_scan --exclude "10.0.0.5,10.20.0.0/24,legacy.example.org"`. Without it the engine behaves, and exports, exactly as before.
