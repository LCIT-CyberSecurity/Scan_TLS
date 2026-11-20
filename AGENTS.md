# Instructions for Orion contributors

This file is the common operating contract for Codex, Claude Code, and human contributors. Keep changes specific to the requested Jira issue and preserve existing behavior outside its scope.

## Before making changes

1. Read the Jira issue in full, including acceptance criteria, dependencies, and all comments in date order. The latest explicit owner decision overrides older instructions. If current requirements conflict, record the conflict and request an owner decision before doing dependent work.
2. Check the repository status, current branch, remotes, latest `_SANDBOX` SHA, open pull requests, and relevant docs/tests. Preserve existing local changes and other contributors' work.
3. Read the relevant application code and tests before editing. Do not assume that a Jira status or PR title proves a feature is complete; compare the actual code and evidence with the acceptance criteria.

## Jira tracking

- `À faire`: not started. `En cours`: active work. `Hold`: blocked or awaiting a decision. `Terminé`: acceptance criteria verified and evidence recorded.
- Before resuming a ticket, reread its comments and follow the latest explicit decision. Do not erase prior decisions; explain superseding decisions in a new comment.
- Record the branch, PR, commit SHA, commands and actual test results (`PASS`, `FAIL`, or `NOT RUN`), Docker/browser verification, limitations, and remaining actions in Jira.
- Use `Hold` only when a real external decision or access issue blocks progress. State the cause, impact, and exact action needed to resume.

## Git workflow

- Never commit or push directly to a permanent branch. Make one ticket branch from the latest `origin/_SANDBOX`, for example `feat/LST-123-short-name` or `fix/LST-123-short-name`.
- Open a separate PR for each ticket, targeting `_SANDBOX`. Keep ticket work independent and synchronize with the latest `_SANDBOX` before continuing to another ticket.
- Promote only one step at a time: `_SANDBOX` → `_EXPERIMENT` → `_UNSTABLE` → `_TESTING` → `main`. Each promotion uses a PR whose head is the previous stage and whose base is the next stage. Never skip a stage or create an automatic merge cascade.
- Merge or deploy only with explicit owner authorization covering that action. A clear standing instruction can authorize a defined set of PRs; do not infer authorization from a Jira comment, ticket status, or prior merge. Never force-push, reset a shared branch, rewrite permanent-branch history, or delete another contributor's branch.
- Do not alter `_EXPERIMENT`, `_UNSTABLE`, `_TESTING`, or `main` when the task targets `_SANDBOX` only.

## Engineering and security

- Preserve the existing APIs, RBAC, scan scope, audit trail, database history, and compatibility unless the ticket requires a change. Prefer additive, reversible migrations. Never change existing scans or published profiles retroactively without explicit user action.
- Keep TLS, IPsec, SSH, and other protocol observations and policies correctly typed. An unknown, untested, filtered, or silent result must never be reported as compliant or absent without evidence.
- Respect target authorization and bounded timeouts, retries, concurrency, and duration. Do not add credential guessing, intrusive protocol actions, secret collection, or out-of-scope network probing.
- Reuse existing UI, workers, scheduler, result storage, and reports. Avoid new navigation or unnecessary dependencies, CSS, CI jobs, or container privileges.
- Do not include passwords, tokens, private keys, or other secrets in source, logs, Jira, or commits. Do not expose user data while validating a deployed environment.

## Validation and delivery

- Run tests and builds requested by the ticket and relevant to the changed areas. Use isolated Docker projects for integration tests; do not reset or delete the persistent Sandbox database or volumes.
- State exactly what was and was not run. Treat existing unrelated failures separately and verify against the base branch when that distinction affects a merge decision.
- Before marking a ticket `Terminé`, verify the merged code and any requested deployment. Report the real merge SHA, PR, test outcomes, and limitations in Jira.
