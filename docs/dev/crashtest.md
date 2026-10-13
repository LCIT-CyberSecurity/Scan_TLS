# CrashTest

A disposable full stack with fictional data for demos and E2E tests. **Demo passwords exist only here** and the seed
refuses to run unless `TLS_SCAN_CRASHTEST=true`; the login page shows a warning banner.

```bash
tests/crashtest/start.sh <vm-host>      # builds, starts (ports 5100 UI, 5110 SSO mock, 5125 mailbox), seeds
tests/crashtest/reset.sh                # destroys only the tlsscan-crashtest project and its volumes
```

Accounts: `admin` / `CrashTest-Admin-2026!`; `operator@`, `user@`, `user2@`, `auditor@crashtest.example.com` /
`CrashTest-Demo-2026!`; SSO mock: any e-mail via `login_hint` (default `alice@sso.example.com`).
Seed: SI Production (Web, Messaging) / Internal (Infrastructure) / Hosting, tags, five lab targets, two policies,
two profiles, two definitions, a daily schedule, SMTP → mailbox sink.

Lab scenarios (`tests/lab`): 443 TLS 1.2/1.3 self-signed · 8443 TLS 1.2 CBC/SHA-1 suites · 8444 expired certificate ·
8445 certificate expiring in 10 days · 8500-8505 private PKI (ACME root/issuing CA: full chain, incomplete chain, wrong SAN, expired, revoked via CRL; Globex: another customer) reachable as `intranet.acme.local`, CA files published on `http://<host>:5130/pki/` · 8446 legacy protocol config · 80 plain HTTP.

DNS lab (`tests/lab/dns`, BIND): `client.test` (AXFR open, internal names), `refused.test` (AXFR refused, dictionary names), `wild.test` (wildcard), `bulk.test` (520 hosts), reverse zone `2.0.192.in-addr.arpa`.
The DNS e2e needs `E2E_LAB_DNS=<address of the lab-dns container>`.

E2E:
```bash
docker run --rm --network host -u $(id -u):$(id -g) -e HOME=/tmp -e E2E_BASE_URL=https://<host>:5100 \
  -v $PWD/tests/e2e:/e2e -w /e2e mcr.microsoft.com/playwright:v1.49.0-jammy sh -c 'npm install && npx playwright test'
```
