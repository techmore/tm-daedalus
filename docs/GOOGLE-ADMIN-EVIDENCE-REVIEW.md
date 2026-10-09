# Google Admin saved evidence and manual review

## Customer workflow

The topic presents the last completed assessment, its collection date, definitive/applicable counts, failures, manual/unavailable results and comparison. A later queued/running/failed attempt is described separately. Workspace observation time is separate from Google evidence collection time.

**Refresh saved Google Admin data** reads the current workspace's stored connection, assessment, checklist and recorded manual notes. It does not contact Google, start a tenant audit, authorize an account, change a schedule or mark notifications read. Idle visible views poll stored status every 30 seconds; active queued/running collection uses five seconds. Hidden topics do not schedule further polling.

A failed refresh keeps the existing dated summary, checklist, expanded evidence, manual notes, selected review item, typed form values and unsaved schedule choice. An inline warning says the saved workspace data may be out of date. An initial failure displays unavailable evidence. Retry keeps the warning until a complete successful read. Identical repeated failures do not rewrite the live warning or add a popup.

## Manual notes through reload and collection

Submitted policy notes are append-only and associated with the current audit connection. **Manual evidence waiting for the next audit** shows the latest recorded note for each check that has not been included in the latest completed assessment on that connection. It includes the source evidence date, recording date, observed/expected values, rationale, source reference, owner and validation method.

A later completed assessment freezes those notes into its own evidence. The waiting list then clears entries that were included. Revised notes reappear as waiting; historical reports remain unchanged. Disconnecting/reconnecting does not apply earlier connection notes to the new connection. The collector and waiting list share the same per-check selection query; more than 1,000 revisions of one check cannot hide another check's older latest note.

Recorded notes do not promote manual or unavailable results to pass. They remain source evidence requiring scoped human validation. A retired review selection stays visible with an explanation and blocks submission until a current item is explicitly selected; typed notes remain intact.

## Read freshness and action guards

Status identifies its organization and observation time. Complete response metadata, assessment counts/percentages, comparison arrays and recorded evidence are validated before replacing the view. Reads use `no-store`, a 20-second deadline, abort signals and request sequences. Late superseded success/error responses cannot overwrite a newer view, and background polling lets an active refresh finish.

Connect, collect, disconnect, schedule and review actions require a successful current read and their current server-derived role/connection/verification conditions. Duplicate writes and reads during writes are blocked. Buttons retain keyboard focus with `aria-disabled`. Outcome feedback stays separate from assessment evidence and survives a failed reconciliation read. Server authorization remains authoritative.

Recurrence approval resets when the latest saved report or audit connection context changes. A saved report from an earlier connection remains reviewable but cannot enable recurrence on the new connection. Stopping recurrence remains possible for an approved admin on a connected customer even when verification/configuration is unavailable. Pending disconnect confirmation is rechecked against the observed connection before submitting. Browser collection, review, schedule and disconnect requests also carry a non-secret connection reference. The server checks it under a database write lock and refuses a replaced connection with 409 before changing data. Existing authorized API clients that omit this optional header retain their established contract.

## Validation and remaining acceptance

Actual Node execution covers failed/partial/malformed/foreign reads, deadlines, late responses, quiet retries/polling, open checklist and pending-note focus, unsaved forms/schedules, retired selections, permissions, write serialization, outcome retention and connection-specific recurrence/disconnect behavior. Authenticated API fixtures cover scoped observation metadata, prior-connection assessment labeling, note submission → reload → mocked collection → frozen report → revision → reconnect/isolation, and independent per-check history selection beyond 1,000 revisions.

These are implemented workflow and controlled fixture receipts. Dedicated OAuth setup, real customer consent and Google tenant audit/recurrence, populated desktop/mobile and screen-reader review, and the full platform operating acceptance remain open. No live tenant collection or CIS attestation is claimed.
