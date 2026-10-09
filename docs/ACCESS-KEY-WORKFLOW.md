# Personal workspace access keys

## Customer workflow

Open **Personal access keys** from the dashboard. The page identifies the workspace and signed-in user before listing keys. Each record shows its last-observed status, creation date, and expiry or revocation date. **Refresh keys** only reads saved records; it does not create a credential or run an audit.

Google-authenticated users can name a key and choose an expiry of 1–90 days. A new key appears once in a selectable, read-only field. Save it privately, then use **I saved this key** to clear that field. Creation remains paused while the new key is visible, so another click cannot overwrite it. The server stores only the token digest. Key-login sessions can review and revoke their own workspace keys; creating another key requires Google sign-in.

An access key can be used at the sign-in page or as `Authorization: Bearer <key>` for authenticated APIs. It uses its owner's current approved workspace membership and role. It cannot select or create another workspace, enumerate unrelated customer summaries, or retrieve another workspace's icon. The CIS client also accepts the personal key in its existing `X-API-Key` header.

Revocation is a durable transition. Repeated normal revocation requests preserve the original date and produce one revocation audit entry. Revoking the current sign-in key returns the browser to sign-in. Subsequent requests revalidate revocation, expiry and approved membership. Existing key-authenticated live feeds revalidate on incoming messages or their five-second receive timeout; this does not cancel work already admitted before revocation.

## Interruption and stale-tab behavior

The account document binds its API reads and writes to the workspace displayed in the page. If another tab selects a different customer, the server rejects the old document's request with 409 before creating or revoking a key. Refresh the page to load the currently selected workspace.

A failed list read retains existing rows, typed form values and keyboard focus. Status becomes **Last observed**, and creation/revocation pause until a successful current read. The fixed refresh control provides retry. Reads and writes have a 20-second browser deadline. Superseded reads cannot replace a later result; no write is automatically retried.

Only one creation/revocation request is allowed at a time. A confirmed write and its follow-up read have separate feedback: failed reconciliation cannot hide the new token or erase confirmed revocation. If a write's response is lost, its result is uncertain. Refresh the saved list before deciding to retry; the server does not redisplay plaintext tokens. A saved key whose token was not received can be revoked and replaced.

The account HTML and key API success responses use `Cache-Control: no-store`. Token values are not written to browser storage by the account script.

## October 9 local acceptance

- Actual API fixtures cover workspace binding, other-workspace icon denial through both key transports, admin demotion, expiration, revoked membership, secret-free scoped inventory, repeat revocation dates/audit count, and self-revocation.
- A real key-login live-feed fixture rejects another workspace and closes the selected workspace feed after revocation and an incoming revalidation message.
- The complete shipped JavaScript runs in Node DOM fixtures: failed/first-load reads, malformed and conflicting responses, timeout/superseded reads, retained nodes/focus/forms, overlapping writes, one-time token preservation, expired status, key-login creation restrictions, invalid login replies, retry and self-revocation navigation.
- In the existing local QA browser, a temporary CSP key was created using the form. A controlled follow-up read failure retained the displayed token. Retry succeeded; saving cleared the field. The real sign-in form opened CSP only, customer switching was unavailable, and self-revocation returned to sign-in. A subsequent Bearer request returned 401. The temporary key is revoked; sanitized receipts contain no plaintext credential.
- A simulated second-tab workspace selection returned 409 on the old account page, retaining the same row, typed name and refresh focus while pausing creation. Restoring CSP and retrying retained those nodes and values.
- Desktop and 390-pixel mobile screenshots were reviewed. The mobile document width matched the viewport; the new-key field was hidden and empty.

Final local validation passed **1,451 tests, one skipped and 446 subtests**. The focused access-key/auth/customer suite passed **54 tests and 16 subtests**, and all **four release-bundle tests** passed with the account script and stylesheet explicitly included. The browser-loaded script matched source SHA-256 `1b09b76125233677e05638a34d6a6bf39b263e2cf736bfe63e90af67a3957b3d`.

This acceptance used an isolated local database with background collection disabled. No production key, provider audit, scanner target or PDF was created or changed. Production activation, actual additional-user onboarding and broader accessibility acceptance remain pending.
