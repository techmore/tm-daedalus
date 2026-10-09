# DNS and website review workflow

## Everyday actions

The DNS and Website topics use one action bar and the shared collection/report callbacks:

- **Check now** collects fresh evidence through the normal workspace API. Its outcome has separate inline feedback; a failed request does not replace the previous collection date with an error message.
- **Monitoring schedule** opens the existing schedule editor and moves keyboard focus to its summary. It does not change the schedule. Saving preserves button focus, prevents a repeated request while pending, and retains the chosen interval on failure.
- **Create PDF report** requests the existing domain-health renderer, then opens Reports for generation progress and download. It captures saved DNS and website snapshots; it does not initiate a scan. All three report-creation entry points share a pending-request guard. This is a browser guard, not a guarantee against requests from separate clients.
- **Refresh saved evidence** reads stored observations. It stays beside the assessment heading, and failed reads preserve findings and collection dates while offering retry.

The lower collection disclosure contains the latest attempt and its recorded date; it no longer duplicates the primary run button. Supporting records, changes, deeper website evidence, history and the schedule editor remain in their existing topic groups.

## Monitoring labels

Schedule labels describe saved configuration, not proof that a worker is running. Daily and weekly intervals retain their actual cadence. A past expected collection time is identified as past rather than shown as a future next run. Missing or malformed schedule data remains unknown.

The action summary uses the same successful saved-data response as the assessment; it makes no separate schedule request. Failed reads mark cached schedule context **Last observed**. A successful retry restores the current saved label. Scheduling still uses the existing server authorization and audit history.

## Reports and recovery

Creation immediately opens the shared report library. The original per-topic 90-second download loop is removed. The library owns progress, failure, refresh/retry and completed downloads. A history-read failure after successful creation retains the creation receipt and directs the user to refresh reports; it is not relabeled as a generation failure.

Approved PDF rendering code, scanner XSL, fonts and historical report assets are unchanged by this UI work.

## October 9 local acceptance evidence

Validation used an isolated copy of the existing local database and report files, with background collection disabled. It was not a production assessment or a production deployment.

The populated browser review exercised:

1. Desktop DNS/Website findings, dates and consolidated actions.
2. A weekly Website schedule saved through the normal API and retained after refresh, with the selected topic preserved.
3. Actual authorized public CSP Website collection: local run 50 completed, comparing with local run 48 and recording two fetched-page differences.
4. Inbox notice 11, its read receipt and its Website review link.
5. Actual CSP DNS collection: local run 51 completed with warnings against local run 47. Its 22 saved evidence differences include record/interpretation/collection metadata; they are not 22 incidents. Three `www` lookups remained unknown, and certificate-history collection was unavailable.
6. Report creation from Website and DNS, library completion at 100%, and browser downloads. Local report 34 retained DNS 47/Website 50; local report 35 retained DNS 51/Website 50. Previously saved active-check evidence remained separately dated.
7. All seven pages of report 34 and all nine pages of report 35 rendered and visually reviewed through the existing renderer.
8. A controlled local saved-read transport failure followed by a real retry, retaining Website findings, dates and focused refresh control. Mobile document width matched the 390-pixel viewport.

Original local database counts remain 49 check runs and 33 report jobs. All 34 original report-directory files and their isolated copies remain byte-identical. New receipts, screenshots, database copies and generated PDFs are private ignored validation artifacts.

Final local validation passed **1,416 tests, one skipped and 446 subtests**. The focused action/history checks passed **61 tests and two subtests**. These checks exercise the actual callbacks, collector routes and renderer; broader product acceptance is still open.

## Remaining acceptance

Production activation requires verified host recovery and authorized SSH access. `/readyz` returned HTTP 200 with database/report storage ready at 04:37 UTC; this does not verify the active source link or deployment recovery. No new production rollout was started for this review.

Every topic still needs populated desktop/mobile acceptance, consistent finding priorities, and a complete screen-reader review. Real customer identity/sharing, sustained scheduling, live provider consent and physical fleet acceptance remain in the [full project report](../PUBLIC-PROJECT-REPORT.md).

## Overview read recovery

The Overview has a fixed **Refresh workspace status** control. It reads saved workspace evidence; **Check DNS & website now** separately requests collection. A status-read timestamp is distinct from each assessment’s evidence timestamp.

An interrupted read keeps the previously displayed priority rows and full evidence cards. The inline warning identifies scanner availability and schedules as **Last observed**, with neutral availability styling. Review navigation remains available. Check and schedule writes pause until a successful current read confirms the workspace and administrator role. The server continues to authorize each write independently.

Reads bypass browser cache, have a 20-second abort deadline, and ignore superseded responses. Background polling leaves an active read or mutation alone. Wrong-workspace, duplicate-area and malformed payloads cannot replace the saved view. An unchanged successful response preserves the actual row/card nodes and keyboard focus. Partial DNS/Website collection retries retain only the unsuccessful request types, including when other saved evidence changes during a poll.

An isolated populated local browser exercised failed reads and real retries at 1,440-pixel desktop and 390-pixel mobile widths. All six priority rows and evidence cards survived; the retry kept focus and cleared the last-observed warning. Website review navigation and page reload retained `#web`. Node callback fixtures additionally cover first-load failure, deadlines, superseded requests, role changes, malformed responses, duplicate writes and partial retries. Actual API fixtures verify current approved membership metadata and member write rejection. This does not close all-topic screen-reader acceptance or production activation.

Final local validation for this checkpoint passed **1,425 tests, one skipped and 446 subtests**; the focused Overview/topic/access suite passed **103 tests and 16 subtests**. The actual loaded browser script matched the final source hash. No new collection or report was requested during this Overview review: the original local database remains at 49 check runs/33 reports, and the isolated copy retains the preceding domain-review cohort’s 51 runs/35 reports.

## Reviewing customers and switching workspaces

**All customers** groups each accessible workspace’s identity, review status, topic coverage, dated evidence, domain ownership and the viewer’s role. More areas requiring review come first within the same status category; these counts are not security scores. The fixed **Refresh customer status** reads saved data with a 20-second deadline. Failed reads retain the actual customer rows and focus, mark availability/access as last observed and pause customer switching until retry succeeds. Unchanged polls keep row nodes; removed memberships move review focus to the fixed refresh control.

**Review customer** opens the selected workspace’s Overview. The sidebar selector preserves the current topic. A switch has one pending request, confirms the returned workspace identity before reloading, and shows failures above the topic panels. A failed attempt restores the selector and leaves the previous workspace visibly identified. Switching the already displayed workspace to Overview needs no API write.

The portfolio API returns only approved memberships. A workspace access key sees only its own workspace, for both Bearer requests and key-login cookies. Dashboard requests, Google Admin requests and the shared report/check/inbox pagers carry the workspace rendered in the document. The server rejects a conflicting `X-Daedalus-Workspace` with HTTP 409 before workspace mutation or expiry updates. Clients without that header retain their existing session/key behavior; each route still enforces its normal authorization.

Populated local desktop/mobile validation exercised CSP/BFS review, retained failed reads, keyboard retry, visible switch failure, BFS Overview/reload and return to CSP. A real temporary CSP key returned only CSP and returned 401 after revocation. Simulating another tab’s BFS selection caused the old CSP page’s bound read to return 409 without replacing its six evidence rows; restoring CSP and retrying returned 200. API fixtures additionally prove revoked membership removal/rejection and no schedule mutation under a mismatched workspace header. Penn Charter membership behavior here is a fixture, not a new live school audit.

The checkpoint passed **1,436 local tests, one skipped and 446 subtests**, **135 focused tests and seven subtests**, and four release-bundle checks. The original local database remains at 49 runs/33 reports; the isolated review copy remains at 51 runs/35 reports. Production activation remains pending host recovery/access.
