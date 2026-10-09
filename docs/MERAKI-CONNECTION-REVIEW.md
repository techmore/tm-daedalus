# Meraki connection, approval and assessment workflow

The Network topic separates saved network evidence from connection setup. An administrator can restore saved organization approvals after a page reload, explicitly refresh Cisco's available organizations, approve a choice for this workspace, request an assessment, and review its progress and saved report.

## Saved connection refresh

`GET /api/meraki/status` returns workspace identity, an observation timestamp, saved key status/verification date, saved approved organizations, administration permission and the current queued/running Meraki report. It sends `Cache-Control: no-store`. This reads local saved state; it does not query Cisco, verify current provider availability or collect an audit.

**Refresh saved connection data** has a 20-second read deadline. Failed, superseded, malformed or foreign-workspace responses cannot replace the prior saved context. A dated inline warning identifies a failed read; the selected organization and typed key remain available for review. Setup actions require a successful current read and are unavailable during a read or write. Repeated failures do not rewrite the same live warning.

Connection wording is **Saved key**, with its recorded Cisco verification date. A failed read uses **Last observed**. Neither wording claims that Cisco is currently reachable or that saved assessment evidence is fresh.

## Choosing and approving an organization

- Saved approved choices load through the status GET, without another provider lookup.
- **Refresh Cisco organizations** explicitly uses the existing authenticated provider lookup. Its choices stay available during the current page session while the saved credential identity matches. Approval flags are reconciled from saved workspace grants.
- Replacing/removing the key discards that old provider catalog. A missing prior selection is retained as an unavailable option, requiring an explicit new choice rather than silently switching the administrator's target.
- A saved approval absent from the last explicit Cisco list is labeled accordingly. Collection is unavailable for that choice, while revocation remains possible when no report is active. A saved approval restored after reload still requires the server's provider availability check when collecting.
- Approval and Cisco availability are separate observations. Meraki access does not establish DNS ownership.

Only one local action is submitted at a time. The requested organization is captured before submission, and its ID appears in the outcome feedback. New key text typed during verification is preserved. Outcomes remain visible if the follow-up saved-state read fails; another action waits for a successful refresh.

Queued/running assessments prevent collection, key replacement/removal and approval revocation. The saved report status remains visible; a read-only Cisco organization lookup and approval of another available organization can still be performed. Server checks enforce these rules independently of disabled browser controls.

## Server admission and response identity

The saved status includes two nonsecret version references:

- `credential_reference` identifies the saved encrypted credential record, its update version and workspace.
- `state_reference` also includes the workspace's saved organization grants.

They are digests, not authentication tokens. Raw API keys and encrypted key bytes are not returned. The short key hint is limited to administrators.

Browser actions send `X-Daedalus-Meraki-State`. A mismatched reference returns 409 before provider work. After any provider lookup, the server acquires the workspace write lock, refreshes the user's scoped-key and admin authorization, and rechecks the captured connection/grant state before committing. Provider requests do not hold that write lock. This also prevents two concurrent requests from admitting two active Meraki reports.

Provider-list/key-save replies capture their credential/state identity before commit, so a later writer cannot relabel the completed provider lookup as belonging to its replacement key. The subsequent saved status read reconciles the page with current state.

Existing authorized clients can omit the header. The server still captures and rechecks their initial state after provider work. Authentication, workspace scope, explicit grants and provider availability checks continue to apply. Headerless clients do not gain permission from a version reference.

## Validation and remaining acceptance

The backend tests exercise scoped status metadata/redaction, saved approvals without provider work, stale references across all six setup/report actions, role and access-key revocation during provider work, post-commit replacement, independent workspaces and concurrent report admission using real SQLite sessions. Provider responses are mocked in these isolated tests.

The Node callback tests exercise read failure/retry, retained forms/selections, deadline/superseded reads, quiet failure warnings, provider choice reconciliation, retired/unavailable selections, action serialization, role/report gates and outcome retention. An actual scoped backend status payload also passes through the real read/render callbacks.

Final local validation passed 1,407 tests, one skipped and 444 subtests; the focused set passed 76 tests and 26 subtests, and release-bundle checks passed four tests. These checks do not establish populated desktop/mobile visual or screen-reader acceptance, another database's production behavior, fresh real BFS/Penn provider collection, complete original-script parity or approved procurement design. Production activation requires a separate deployment and authenticated workflow receipt. Existing approved PDF templates, snapshots and scanner assets are unchanged.
