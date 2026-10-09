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

Production activation requires verified SER8 access and recovery/source inspection. Actual additional customer Google users, TXT publication, approved sharing, succession, future expiry/renewal and wider accessibility review remain open. This local walkthrough does not establish those outcomes. Audit-history refresh/pagination and request-list recovery still need the same complete customer review contract.

The previous source `41d0070` passed backend CI **37891108104**. Linux CI **37891108169** passed four scenarios but failed interrupted-bridge recovery with one rejected event. That separate scanner issue remains open; see [scanner recovery diagnostics](SCANNER-LIVE-VALIDATION.md#rejected-recovery-evidence).

The published member implementation `8fa2080dd6b0401b26b6ff3012f73f45c5ce76c3` subsequently passed backend CI **37895490255** on Python 3.11/3.12 and all five Linux scenarios in **37895490130**. This includes interruption with the preceding scanner bundle; a separate frozen-payload correction now has its own regression and real Mac proof. Production/member acceptance remains as listed above.
