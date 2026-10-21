# Daedalus deployment ready

Audit baseline: `ebe2d7515cf5f9305360bd9b886b549778c0cbcb` on `main`, October 20, 2026 (America/New_York).

[Persistent blueprint](https://github.com/techmore/tm-daedalus/issues/17) · [Deployment milestone](https://github.com/techmore/tm-daedalus/milestone/1)

## Required gates

- [Reconcile live source and prove current release recovery](https://github.com/techmore/tm-daedalus/issues/11)
- [Fail closed when a scanner has no known authorized scope](https://github.com/techmore/tm-daedalus/issues/12)
- [Use protected staging for deployment archives and extraction](https://github.com/techmore/tm-daedalus/issues/13)
- [Validate the real customer onboarding and populated portal workflow](https://github.com/techmore/tm-daedalus/issues/14)
- [Qualify scanner fleet and signed macOS distribution for the intended rollout](https://github.com/techmore/tm-daedalus/issues/15)
- [Define release gates, operating limits and retention](https://github.com/techmore/tm-daedalus/issues/16)

## Evidence contract

GitHub tracks issues and features across sessions. Gate completion, exact-commit CI, deployed source identity, fresh recovery evidence and operator/customer acceptance are separate facts. Do not use a passing workflow or a merged pull request to declare production ready. Counts represent completed gates, not estimated engineering effort. Keep unverified gates open and record any explicit rollout scope decision.

The October 20 audit inspected source, existing reviews, issue/PR history, CI and repository protection settings. It did not access production, change business data, initiate network scans, validate credentials, or conduct new customer acceptance. main had no branch protection and no rulesets in the audit reads; the linked CI gate tracks the policy decision rather than silently changing it.

## Audit reconciliation

The audited main passed Python 3.11/3.12 and all five managed Linux scanner scenarios. SQLite WAL/busy timeout, same-origin protection and scoped bridge enforcement are already in main (#5). Nikto already queues and returns 202; the older review’s inline-execution finding is stale. The local unknown-scope fallback and shared deployment staging remain separate implementation gates above. No exploit or live scan was attempted.

Review existing PRs #7 (lint), #8 (platform map), #9 (UI/accessibility) and #10 (API hardening) before choosing a release; do not recreate their changes. Native macOS workflows are path-filtered, so Linux/backend green does not imply native sign-off for this main commit. [The project report](../PUBLIC-PROJECT-REPORT.md) retains dated deployment history and a failed activation with rollback unverified; establish the actual live revision before another rollout. Broader Google Admin/Meraki/full-platform acceptance must be explicitly included or excluded from the initial customer scope.
