# Endpoint evidence review and refresh

The endpoint topic leads with the latest saved assessment, its device/profile/collection date, failed and unassessed checks, workspace assessment coverage, changes, supporting results and separate client check-ins.

## Customer workflow

**Refresh saved endpoint data** reads the current workspace's saved status, published profiles, reports and changes. It does not run an endpoint audit, rotate a key, publish a profile, generate a PDF or mark a notice read. Updated check-ins are also read every 15 seconds while the endpoint topic is visible, and when returning to a visible page. Client presence and collected assessment recency retain their separate server thresholds.

A failed read retains the preceding assessment counts, dates, devices, profiles, reports, changes and profile selection. A dated inline warning states that coverage, check-in status and setup may be out of date. Cached presence badges say **Last observed** and lose the current-presence color. A retry retains the warning until a complete successful read. An initial failure says unavailable instead of claiming there are no enrolled devices or saved reports. No new modal or completion toast is added.

Existing report nodes are reused when their saved metadata is unchanged. Open reports, loaded check evidence, nested category disclosures and focused PDF controls remain available as new reports arrive. An earlier-report group opens when an active review moves into it. If a focused report leaves the returned window, focus moves to refresh. Unchanged reads do not rebuild evidence lists or profile options. A removed selected profile falls back to a currently published compatible profile.

## Read and setup contract

- All four responses identify their organization. They must match the rendered workspace. Status includes the server's observation time.
- Requests use `no-store`, an abort signal, a 20-second deadline and a request sequence. Late superseded successes or failures cannot overwrite a newer view. Background reads let an active refresh finish.
- The complete response set and its collection shapes, unique positive row IDs, coverage counts and report summary metadata are checked before rendering. A partial HTTP failure or malformed set preserves the preceding view. These are separate database reads; no single database transaction snapshot is claimed.
- Setup actions require a successful current read and the server's management flag, as well as an admin role. During a read, failed read or pending setup operation, their handlers reject writes. Controls use `aria-disabled` to retain keyboard focus. Server authorization remains authoritative.
- A setup operation invalidates the preceding setup observation until a successful reread, including uncertain network failures. Duplicate setup actions are blocked. Profile-publish and client-key outcomes use separate feedback, so a failed reconciliation read cannot erase a successful action's explanation.
- The selected profile is captured before requesting a client key. A key rotation message continues to explain that existing client configurations must be replaced after the reread.
- The device list is bounded to 250 rows; truncation is disclosed and workspace coverage includes all enrolled devices. Existing endpoint report/change/profile APIs still return their bounded latest windows (50/100/100); complete older endpoint assessment pagination remains open. Generated PDF history uses its existing separate pagination.

## Evidence and remaining acceptance

Actual Node callbacks exercise initial/repeat/partial failures, malformed and foreign response sets, late success/error suppression, deadline retry, background concurrency, saved evidence and profile selection, typed form retention, cached presence, current permissions, setup serialization/reconciliation, key configuration selection and preserved open report/PDF focus. Authenticated API fixtures exercise organization metadata, non-cached reads, workspace switching, hidden prior report/profile downloads and revoked client keys.

This work improves saved assessment review. Populated portal desktop/mobile and screen-reader acceptance, trusted signed/notarized macOS 26 distribution, physical managed endpoint collection/check-ins and complete older assessment pagination remain required. It does not establish a CIS attestation or close the full platform goal.
