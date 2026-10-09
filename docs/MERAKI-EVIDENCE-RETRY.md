# Reviewing saved Meraki evidence after a failed read

The Network view exposes saved observations, inventory, security controls and UniFi planning from a completed assessment. The current summary and an opened report disclosure share one request for that saved report. These reads do not contact Meraki or start another audit.

## Recovery behavior

- Failed transport, HTTP errors, malformed envelopes, a different report ID or a different workspace ID produce an inline warning and **Retry review observations** or **Retry report details**.
- A failed read is removed from the request cache. Closing and reopening a failed disclosure can retry it; the loaded marker is set only after successful rendering.
- A request has a 20-second abort deadline and uses same-origin credentials with `no-store`. The server already sends `Cache-Control: no-store`; its response now includes the customer workspace ID alongside the report ID. The nested Cisco organization retains its separate identity.
- Repeated clicks while a read is pending do not duplicate it. The retry button stays in place during that read and exposes its unavailable state through `aria-disabled`.
- Successful retry moves focus from the removed retry control to the containing report summary, or the observation container when it has no report summary. If the user moves focus elsewhere while waiting, completion leaves that focus alone.
- Detached views ignore late results. Warnings use fixed text rather than raw transport/server errors. Existing classes retain the CSP theme, without another popup.

The check validates response identity and the outer summary/findings shape. It is not a complete validator for every nested Meraki projection. Successful saved snapshots remain cached for the page; this does not refresh their collection date or establish current device state.

## Validation and remaining acceptance

`tests/test_meraki_evidence_retry_ui.py` executes the actual request, shared read helper and public loader callbacks using a small DOM fixture. It exercises failure/retry, reopen, shared pending requests, malformed/foreign responses, deadline recovery, focus, detached views and GET-only behavior. The existing topic tests execute the actual bounded summary renderer; scoped backend tests verify workspace metadata, `no-store`, existing report content and cross-workspace denial.

Final local validation passed 1,367 tests, one skipped and 432 subtests; release-bundle checks passed four tests. These fixtures do not establish populated browser visual or screen-reader acceptance. The broader report library still rebuilds cards on changed history reads; preserving every expanded nested disclosure and focused report control across library refreshes remains work. Connection/scope management, original script parity, real provider coverage and procurement design remain separate acceptance requirements.

No approved PDF template, historical snapshot, catalog price or scanner asset is changed by this recovery implementation. Production rollout and normal saved-evidence reads must be verified separately from local tests.
