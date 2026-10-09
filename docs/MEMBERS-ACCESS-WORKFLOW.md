# Members and access review

## Customer workflow

Members & access puts pending requests, approved member count, administrator coverage and the observation date before the workspace audit history. **Refresh members** reads saved access. Overview's pending requests use the same snapshot and decision controller.

An approved shared member starts as a user. An admin can promote an approved user, then switch their own account to user once another approved admin exists. The resulting page reload reflects the current role. Users see only their own approved membership and no member-management actions. Removing another approved user ends their workspace access; rejoining requires a new request and approval.

Approval and role changes require current domain verification or a current recorded workspace approval. Denial and shared-user removal remain available when that approval has closed. The last approved admin cannot be demoted. Admin memberships cannot be removed through shared-user removal.

## Refresh and decision behavior

- Failed reads retain member rows, dates, focus and pending requests, mark them as last observed and pause changes. The fixed refresh action permits a real retry.
- Successful identical reads retain row nodes, keyboard focus and an open inline confirmation. Background refresh keeps valid controls usable. A decision supersedes an in-flight background read, so its older response cannot restore the pre-decision state.
- One pending write guards both Overview and Members actions. Confirmed outcome feedback survives a failed following read. An unconfirmed response asks for a fresh read before retry; writes are never automatically retried.
- Reads and writes have a 20-second deadline and bind to the displayed workspace. The browser submits a membership state reference, including its latest recorded transition, so returning to the same role or status cannot revive a decision from an earlier request episode.
- The server serializes administrative membership changes under the workspace write lock, rechecks the actor's membership and key/session after acquiring the lock, and checks the target reference before mutation. Concurrent promotion/removal cannot revoke an admin; simultaneous self-demotions retain an approved admin.
- Access-request submission has its own pending-write guard, bounded transport and reply validation. A timeout directs the requester to inspect saved requests before trying again.

The workspace audit history preserves actor and recording date. New approval, denial, removal and role events include the affected email and a readable summary; earlier events retain their original details.

## October 9 validation

An isolated local copy exercised denial → a new request → approval as user → successor promotion → owner self-demotion → successor restoring the owner → successor self-demotion → shared-user removal → a new request → approval. The former admin's actual API read returned only their own user membership, and their page had zero member-management actions. The final copy retains the original owner as admin and the shared member as user.

A controlled read failure followed by a real retry retained the same member node and refresh-button focus, paused decisions and cleared the warning after recovery. Populated 1440-pixel desktop and 390-pixel mobile screenshots were reviewed; the mobile page had no horizontal overflow. Loaded module/dashboard hashes matched current source. This uses the development demo identities, not real customer Google accounts.

Final local validation passed **1,470 tests, one skipped and 446 subtests**. The member/API/scanner-diagnostic focused suite passed **42 tests and seven subtests**. Fixtures cover stale request episodes, role cycles, expired actor keys during lock admission, real concurrent decisions, duplicate submits, malformed replies, read/write deadlines and background-read supersession. The deployment archive was built and verified. All 34 original report-directory files remain byte-identical; the original database retains 49 external runs and 33 reports, and the isolated copy retains 51 runs and 35 reports. No new collector, scanner or PDF run was initiated for this member walkthrough.

## Remaining acceptance

Production activation requires verified SER8 access and recovery/source inspection. Actual additional customer Google users, TXT publication, approved sharing, succession, future expiry/renewal and wider accessibility review remain open. This local walkthrough does not establish those outcomes. The request-list and audit-history follow-ups below have separate local review evidence. [Customer creation](CUSTOMER-ONBOARDING.md#customer-creation-review--october-9-implementation-checkpoint) now has its own local review; production creation and real customer onboarding acceptance remain open.

## Recorded action history — October 9 follow-up

Members now shows how many recorded workspace actions are loaded, their observation date, a fixed **Refresh action history** control and **Load older actions**. Each event identifies its actor and time to the second; readable access/override summaries precede the existing saved-detail disclosure. Narrow screens stack each action's heading and timestamp, with readable actor/time text.

The read-only API retains the existing `events` records and adds workspace/observation metadata, total count and an ID-based older-page cursor. It validates limits/positions, refuses foreign or unknown positions, requires a current admin and returns `Cache-Control: no-store`. The UI requests 40 records per page, binds the rendered workspace, validates each returned page and bounds transport/body reads to 20 seconds. Newer actions do not displace an already loaded older review boundary.

Failed reads retain existing rows, open evidence and focus, mark the last successful read date and offer retry. Unchanged successful reads reuse the same nodes. Loading the final older page moves focus from the disappearing older button to refresh. Action-history failures do not overwrite confirmed member decisions. Direct `#members` startup and later reads share one controller; an actual browser walkthrough found and corrected duplicate initialization that had replaced rows during retry.

The isolated browser retrieved all **220 saved actions** without duplicates, retained their full review depth after refresh, and preserved the same row/open disclosure/keyboard focus through a controlled read failure and real retry. Reload stayed on Members. Populated 1440-pixel desktop and 390-pixel mobile views were reviewed, with no horizontal overflow or clipped actor names. All 34 original local report files remain identical; original and review databases retain 49/33 and 51/35 external-run/report counts respectively. No audit, scan or PDF was requested for this history review. Production activation and broader accessibility/customer acceptance remain open.

Final local regression validation passed **1,489 tests, one skipped and 451 subtests**. API/controller fixtures cover complete pagination, inserts during review, foreign/unknown positions, invalid limits, demotion denial, unchanged evidence, response-body deadlines, stale replies, literal rendering and direct Members startup. An earlier sandboxed run could not open required loopback/PDF/Swift resources; the authorized full runs completed successfully. This is local implementation evidence, not production activation or a complete accessibility audit.

The previous source `41d0070` passed backend CI **37891108104**. Linux CI **37891108169** passed four scenarios but failed interrupted-bridge recovery with one rejected event. That failed run remains recorded and its particular rejection cause is unproven; see [scanner recovery diagnostics](SCANNER-LIVE-VALIDATION.md#rejected-recovery-evidence).

The published member implementation `8fa2080dd6b0401b26b6ff3012f73f45c5ce76c3` subsequently passed backend CI **37895490255** on Python 3.11/3.12 and all five Linux scenarios in **37895490130**. This includes interruption with the preceding scanner bundle; a separate frozen-payload correction now has its own regression and real Mac proof. Production/member acceptance remains as listed above.

The action-history source `6b90c89b457651f472f1868d796f21288a89fe31` passed backend CI **37900891080** on Python 3.11/3.12 and all five Linux scanner scenarios in **37900891036**. These results apply to that source; production activation remains unverified.

## Account workspace requests — October 9 follow-up

**Add or join workspace** and the account page without an approved workspace now share a saved-request controller. **Refresh workspaces** reads existing memberships and requests; it does not run an audit. The summary shows approved workspace and pending-request counts with the observation date. Rows distinguish awaiting approval, approved role, declined requests and removed access. The recorded request time comes from the latest request event; membership creation is not presented as the submission date. Missing historical request dates remain explicitly unavailable.

The API is account-owned, includes user identity and observation metadata, and returns `Cache-Control: no-store`. Workspace-bound keys cannot read the account's other workspaces. The browser validates identity, row fields, dates and unique workspace IDs. Transport and response-body reads have a 20-second deadline; a superseded read cannot restore old access. Failed reads retain rows, focus and dates, label access as last observed, and pause switching until a successful retry. Unchanged successful reads reuse row and selector nodes. Request confirmations and typed form contents survive an independent read failure.

Actual browser review exposed an unchanged-session cookie rewrite during dashboard polling, which could overwrite a later identity or workspace selection. Ordinary context reads now assign the workspace only when it changes. Tests confirm that normal and key-session dashboard reads do not issue an unchanged identity cookie, while login, initial workspace selection and logout retain their required cookie writes. This corrects the exercised read-response race; it does not establish a complete session-lifecycle audit.

An isolated local demo member submitted a BFS request, retained confirmed feedback through a controlled following read failure, and retrieved the saved pending request with its new timestamp on retry. The same node, typed input and refresh focus survived failure/retry. After normal admin removal from CSP, the account page reloaded with no approved workspace, retained both requests, and supported another failed read/retry. A new CSP request appeared in both account and dialog views; the admin approved it as user. The separate BFS request was declined. Final CSP roles remain owner admin/shared member user; no school access was granted in this walkthrough.

Populated 1440-pixel desktop and 390-pixel mobile dialog/account screenshots were reviewed. The final desktop dialog had no horizontal overflow. All 34 original report-directory files remain byte-identical; original and review databases retain 49/33 and 51/35 external-run/report counts. No collector, scanner or PDF was requested. Final local validation passed **1,501 tests, one skipped and 459 subtests**; the focused suite passed **91 tests and eight subtests**. Production deployment, real Google-user onboarding, customer creation, ownership and broader accessibility acceptance remain open.
