# Scanner recovery and repository sync — 2026-10-12

## Completed

- TM-NmapUI main fast-forwarded from 2828bd36 to 0fc510e2 and pushed. The unattended-operation branch is also pushed at the same revision.
- Scanner cancellation now accepts the exact observed source job identifier across local UI sessions. Registry checks the identifier under its lock, so stale requests cannot cancel replacement jobs. Bridge commands retain namespace restrictions.
- Interactive per-device service scans use Nmap's 120-second host timeout and a 135-second process deadline. Incomplete devices are recorded in durable job details and completion summaries instead of emitted as successful empty results. Host-level progress is durable and uploaded.
- Scanner suite: 679 passed, 28 skipped. Meraki suite: 145 passed.
- Meraki-Security-Baseline main's 25 existing unpublished commits were pushed at 73e881a. The local topology branch has no commits absent from local main.
- Updated Daedalus source bundle packages clean TM-NmapUI revision 0fc510e2.
- Local managed scanner installed in release b771a437dd31cb9344abf4c21a14ebfa74185f1278d796dc1090e8494e4af08a, reusing its existing Python/browser dependencies; source changes do not alter requirements. Data and enrollment remain outside the source release.
- Live subnet scan started 08:07:57 EDT on automatically detected 10.20.0.0/24. Discovery found 13 hosts; native app displays their MAC/vendor evidence. Service scanning remains in progress at this checkpoint.
- External route discovery is active and displays private gateway and public hops. Cloud agent 2 is online; new run a9a6300f-81f2-473c-8167-c18822ba3c90 is visible remotely, with acknowledged events and zero pending uploads at 08:08:46 EDT. Queue clearance does not mean scan completion.

## Remaining consolidation

- TM-NmapUI swift-native has 29 commits absent from the current main, including a separate native scan/report/privilege implementation. A merge-tree preview finds conflicts in .gitignore, README.md, install.sh, scripts/nightly_product_eval.sh, static/js/auto_scan_ui.js, and static/js/settings_tab.js. Integration needs reconciliation and native validation; it has not been merged or discarded. Alpha checkpoint remains preserved.
- CSP-CIS_Audit has substantial uncommitted client/Tahoe work and no configured remote. It cannot currently be pushed.
- remote-control has substantial uncommitted Go/Swift/deployment changes plus divergent feature branches. It is not fully consolidated or clean.
- CyberSecurityPilot.github.io has local theme/config edits and an untracked .DS_Store.
- xcode-TM-DNS has substantial uncommitted native/Rust/web work. Its current branch starts at the same commit as main.
- Meraki has one remaining local .gitignore edit; this was not included in the existing main push.

These remaining trees require their own diff review and validation before claiming all repositories are synchronized. No history was rewritten and no experimental branches were deleted.
