# Exposure evidence operations

Exposure entries are explicit operator records; Orion does not determine Internet accessibility. Use a real, authorized external network vantage point or a reviewed and dated network control as the evidence source. Do not use a public address, DNS record, reverse DNS result, DMZ label, NAT mapping, reverse proxy address or scan from inside the network as proof by itself.

Operators may submit evidence with its method, source, justification and confidence. An administrator reviews the cited evidence and marks it validated. A pending proposal never affects contextual risk. To withdraw a finding, set the current record to `unknown` or replace it with newly reviewed evidence; historical scan snapshots stay unchanged.

Run migrations using the deployment's documented install/update command. Before a deployment, back up the database and storage volume. Verify the schema head with `alembic heads` in the backend environment and check that the migration path has one head after all independently developed ticket branches are integrated. If the upgrade fails, restore the pre-upgrade database backup; do not delete old run/report files. No additional container capability, network permission or external service is required.

For a repeatable check, create or choose a test target and record a pending exposure. Confirm it is still treated as unknown in a new run. Validate documented test evidence as ADMIN, queue another scan and check that the grade and intrinsic severity remain the same while contextual risk follows `exposure-risk-v1`. Update exposure once more and verify that both previous run snapshots still show their original states. No live connectivity probe is part of this check.
