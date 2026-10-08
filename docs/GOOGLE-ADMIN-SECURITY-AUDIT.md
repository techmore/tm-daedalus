# Google Admin security audit and ongoing reporting

Added October 8, 2026. **Status: initial source implementation and local validation complete; production activation, real OAuth consent and CSP/BFS tenant acceptance remain pending.** Existing Google sign-in authenticates a portal user with `openid profile email`; the separate Drive connection exports reports. Neither establishes Google Admin audit authority.

## Implemented source scope

The portal now includes a **Google Admin security** topic, overview/portfolio status, separate Admin OAuth routes, encrypted workspace-bound refresh-token storage, a ten-item checklist, manual evidence records, immutable JSON/PDF reports, comparison notices and opt-in daily/weekly/30-day scheduling. Recurrence requires an explicit acknowledgment of a completed report on the current connection. Disconnect cancels active jobs; authorization is checked again under a persistence fence before saving collection or completing the report. Server restarts fail interrupted jobs and release their collection locks.

The initial scope manifest requests `openid`, `email`, and only the four Directory read-only scopes for customer, domain, user and role management. It validates the customer/domain before storage and again during collection. Entire-customer authorization is explicit; the same customer cannot silently attach to two workspaces. The initial collector does not request Reports, OU/group, device, Gmail, Drive-content, user-security or domain-wide-delegation access.

Only GA-03 has a definitive API criterion: enrollment and enforcement for active administrator records returned by Directory users, with complete population/boolean evidence. It does not establish group-derived admin coverage, factor type or effective OU/group policy. All other checks remain manual review or unavailable. Roles and assignments provide review context; API reads never change Google settings. Collections have response, row, pagination and elapsed-time bounds, and minimize retained user fields. Missing fields and partial coverage cannot produce passes or confirmed removals.

Manual records include source evidence time, recording time, reviewer, policy scope, observed/expected settings, rationale, private source reference, owner and validation. They append to the next assessment; they do not rewrite historical reports or upgrade a manual check into a pass. Comparisons distinguish account/role observations, coverage, baseline and manual evidence changes. Notifications use the existing workspace inbox; outbound email is not implemented by this feature.

Acceptance targets specified by the user: **CSP (`cybersecuritypilot.org`) and `bfs.org`**, with independent consent and report history. The local environment currently has neither dedicated Admin OAuth credential configured. Production credential readiness and domain verification must be checked during rollout; an earlier dated project report recorded BFS ownership as pending, which is not a fresh production observation. No live Google tenant has been assessed by this implementation.

See [source and validation evidence](../INTEGRATION-READINESS.md) and the rollout steps below. The following design covers both this initial implementation and the staged extensions still pending.

## Section and baseline

Add a workspace topic named **Google Admin security** beside the existing network, domain and endpoint topics. Lead with last successful collection, connection health, assessed coverage, findings needing review and evidence age. Include connection details, checklist, recommended actions, saved assessments and comparison history.

Use two references with different purposes:

- [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1) for the security-program rationale and reporting crosswalk.
- [CIS Google Workspace Benchmark](https://www.cisecurity.org/benchmark/google_workspace) for configuration-specific recommendations after obtaining and reviewing the exact edition/version, profile and applicable usage rights. Its public landing page did not establish an exact version during this review; do not invent one or assign unverified recommendation numbers. CIS advertises the free PDF for non-commercial use; establish suitable rights for this service before incorporating benchmark material.

Supplement both with [Google's security checklist](https://support.google.com/a/answer/7587183) and [administrator account guidance](https://support.google.com/a/answer/9011373). Settings depend on Workspace/Cloud Identity edition. Education domains need explicit student/staff/admin OU and group applicability, age-based access and approved exceptions; the existing [school checklist](../site/Chrome_Moysle_googleadmin/school-mac-security-roadmap.html) is supporting guidance, not evidence that policies are deployed.

The initial crosswalk below is a CSP interpretation at **control level**, not an official CIS mapping, safeguard assessment or compliance attestation. Pin the exact safeguard IDs and benchmark recommendation IDs only after reviewing their authoritative text. Existing Meraki CIS v8 mappings and historical reports retain their original version.

## Read-only connection and tenant validation

Implement a separate Google Admin audit OAuth connection. Prefer a dedicated Google Cloud project so audit authorization and revocation are independent of login and Drive export. Google notes that token revocation removes grants across clients within a project. Use Google's maintained OAuth libraries and [server-side authorization-code flow](https://developers.google.com/identity/protocols/oauth2/web-server); request offline access for recurring collection, validate returned grants and handle revocation/reconsent. A public multi-customer app requires the appropriate external audience and Google verification; an internal app serves only its own organization. See [consent configuration](https://developers.google.com/workspace/guides/configure-oauth-consent).

Proposed application security contract:

1. Only an active portal workspace administrator for a verified domain can start or replace the connection. OAuth consent is performed by a Google administrator with the specific read privileges required by each API; portal admin membership alone grants no Google privileges. Default to a delegated audit account where supported; record privilege-dependent gaps instead of requiring standing super-admin access for all collection.
2. Bind the authorization request to a single workspace, authenticated initiating user, intended domain and expiring one-time state. Use nonce validation for an OIDC identity and PKCE where supported. Validate issuer, audience, signature, expiry and identity claims through the library. A requested `hd`, returned email suffix or successful login is insufficient tenant validation.
3. Probe `customers.get(my_customer)` and `domains.list` with the consented token. Confirm the intended verified domain belongs to the returned customer; pin its immutable Google customer ID. Reject mismatches before storing a usable connection. Recheck this binding on refresh/collection; never accept a browser-supplied customer ID as proof.
4. Explicitly record whether authorization covers only the selected domain or the entire Workspace customer. Directory roles and many policies/events are customer-wide; OAuth scopes do not restrict access to an email domain. Multi-domain customers require an approved customer-wide audit scope before collecting those resources. A verified alias or secondary domain does not authorize exposing other domains' users. Without that grant, show tenant-wide checks as unavailable and collect only resources that can be reliably bounded.
5. Record requested/granted scopes, consent identity, customer binding, approved population/OUs, privileges, validation time and connection health. Reject broader unexpected grants for this dedicated audit project rather than silently calling them read-only.
6. Encrypt refresh tokens on the server; exclude tokens, authorization codes and secrets from logs, browser responses, evidence and PDFs. Scope every credential/job/download to its owning workspace. If one customer appears in multiple portal workspaces, require separate approved sharing rules; do not automatically merge or share evidence.
7. On disconnect, stop queued/future collection, revoke the dedicated grant, remove the token and preserve historical assessments under the retention policy. On invalid grants or lost privileges, show reconnect/coverage failure while retaining the dated last successful assessment.

### Scope manifest

All scope suffixes below use `https://www.googleapis.com/auth/`. These are staged requests, not a request to consent to all scopes at once. Add only scopes required by the selected audit population and checks.

| Collection stage | Scope suffix | Evidence and limits |
| --- | --- | --- |
| Tenant binding | `admin.directory.customer.readonly`, `admin.directory.domain.readonly` | Customer/domain identity and verification metadata; not tenant security configuration. |
| Core account assessment | `admin.directory.user.readonly` | Bounded user inventory, lifecycle, OU, admin and returned 2SV fields; exclude recovery contacts and unrelated personal fields. |
| Privilege assessment | `admin.directory.rolemanagement.readonly` | Roles, privileges and assignments; complete pagination and role scope required. |
| Population and inheritance context | `admin.directory.orgunit.readonly`, `admin.directory.group.readonly`, `admin.directory.group.member.readonly` | OU/group membership context; not proof of effective policy. Request only for applicable checks. |
| Change/event evidence | `admin.reports.audit.readonly` | Selected admin/login/token events with explicit customer, application and time range; event history does not prove current effective settings. |
| Optional usage evidence | `admin.reports.usage.readonly` | Dated usage/security indicators; delayed/missing report dates stay explicit. |

Sources: [Directory scopes](https://developers.google.com/workspace/admin/directory/v1/guides/authorizing), [customer probe](https://developers.google.com/workspace/admin/directory/reference/rest/v1/customers/get), [domain listing](https://developers.google.com/workspace/admin/directory/reference/rest/v1/domains/list), [activity scopes](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list), [usage scopes](https://developers.google.com/workspace/admin/reports/reference/rest/v1/userUsageReport/get).

Exclude Gmail message access, Drive content access, write-capable Directory scopes and domain-wide delegation from the initial design. `admin.directory.user.security` permits security operations and has no read-only counterpart in the Directory scope list; do not request it to claim a read-only token/app-password audit. Use manual evidence for unsupported checks. A later API extension requires an independently reviewed scope manifest and new consent.

## Initial audit checklist and why settings may change

All rows start **not assessed**. Establish the customer edition, approved population and expected criterion before assessing. Console evidence must include capture time, reviewer, policy path, OU/group, inheritance/override context and applicable edition. Use private screenshots or exports with unnecessary personal data redacted; a checked box alone is not evidence.

| ID / check | Initial evidence method | Proposed target and reason for a change | CIS Controls v8.1 crosswalk |
| --- | --- | --- | --- |
| GA-01: Account inventory and lifecycle | Directory users plus approved HR/student roster and reviewer evidence | Identify orphaned, dormant and departed-user accounts; review and suspend/remove according to an approved lifecycle policy. No login timestamp alone proves an account is unnecessary. | 5 Account Management |
| GA-02: Admin privileges and recovery | Users, role assignments and manual recovery procedure | Named separate admin accounts, limited delegated privileges and independently managed recovery-capable admins reduce standing privilege and recovery risk. Review broad grants before removing them. | 5 Account Management; 6 Access Control Management |
| GA-03: 2-Step Verification | Returned `isEnrolledIn2Sv` / `isEnforcedIn2Sv` plus effective policy evidence | Require 2SV for applicable populations; prioritize phishing-resistant admin authentication. API booleans do not identify the factor type, exception policy or every authentication path. | 6 Access Control Management |
| GA-04: Authentication and session policies | Console evidence for password, SSO, session and recovery rules | Align effective rules and approved exceptions to the chosen baseline; inspect inherited settings and IdP behavior before recommending a change. Preserve tested recovery access. | 4 Secure Configuration; 6 Access Control Management |
| GA-05: Third-party apps, OAuth trust and delegation | Selected token/admin events plus console app-access and delegation inventory | Review trusted apps, broad grants, legacy access and delegated service identities against an approved inventory. Missing token events do not prove no grants exist. | 2 Software Inventory; 6 Access Control Management; 15 Service Provider Management |
| GA-06: Gmail protection and sender authentication | Console phishing/spam/attachment settings plus existing DNS SPF/DKIM/DMARC evidence | Reduce spoofing and malicious-message exposure; separate domain DNS observations from tenant Gmail enforcement. Confirm sending services before stricter policy. | 9 Email and Web Browser Protections |
| GA-07: Drive, Groups and Calendar sharing | Console external/public sharing and group rules; limited Directory group context | Reduce unintended disclosure with approved sharing boundaries and documented business exceptions. Do not imply this audits file contents or every individual ACL. | 3 Data Protection; 6 Access Control Management |
| GA-08: Audit logs, alerts and review | Reports API coverage plus console alert rules and operational review/retention evidence | Ensure relevant events are collected, reviewed and retained under the agreed policy; alert-rule configuration and delivery need separate validation. | 8 Audit Log Management; 17 Incident Response Management |
| GA-09: Devices and Chrome policy | Initially manual MDM/Chrome console evidence | Confirm approved browser/device controls, extensions and managed access for scoped populations; add device/policy APIs only after confirming their read-only scopes and privilege needs. | 1 Enterprise Asset Inventory; 4 Secure Configuration; 9 Email and Web Browser Protections |
| GA-10: Data retention, recovery and incident readiness | Manual Vault/retention, recovery and response evidence | Match legal/operational retention and recovery requirements; a retention setting is not proof of independent backup or a successful restore. | 3 Data Protection; 11 Data Recovery; 17 Incident Response Management |

Directory field semantics: [User resource](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users). Initial priorities are a proposal: GA-02/03 first, then GA-05/06/08, followed by remaining applicable checks. Each domain's actual evidence and constraints determine its action order.

Every recommended change needs this chain: **observed value → scoped expected value → source/version/reference → risk/reason → proposed change → owner → validation**. Record dependencies, effect on users, exception rationale/expiry and rollback plan. The audit produces recommendations; the domain administrator separately approves and performs configuration changes.

Example: a scoped admin account explicitly returns 2SV enforcement false. Record that observation and its collection time; attach effective-policy/exception evidence before concluding enforcement is missing. Recommend the applicable admin 2SV policy based on Google admin guidance and the reviewed baseline, map it to CIS Control 6, and validate by recollecting the API field plus effective-policy and authorized authentication evidence. Missing fields remain unknown; enrollment alone does not prove phishing resistance.

## Ongoing report contract

Add this topic to the workspace overview, immutable report library, reporting schedule and dated change notices once implemented. Keep the Google customer identity and evidence private to the owning workspace. Append new PDF sections using the established report style; preserve existing sections and historical artifacts.

Each frozen assessment should contain:

- Workspace/customer binding, approved domains/OUs/populations, edition, initiating actor, start/completion times in UTC and source freshness times.
- Versioned CSP checklist and evaluator, CIS Controls version, selected benchmark version/profile (or explicitly pending), exact source references and manual evidence provenance/digests.
- Per-check observed/expected value, API or manual source, population/coverage, status, risk explanation, recommendation and applicability. Store only selected necessary fields, not entire user records or unrestricted event payloads.
- API pagination completeness, permissions, errors, unsupported/edition limitations, report latency and manual evidence age. Missing values, empty ambiguous responses and incomplete collections never become passes.
- Action owner, suggested review date, approved exception/expiry, decision and verification evidence. Later decisions should be append-only records or new snapshots, not edits to a historical assessment.

Use `pass`, `fail`, `manual_review`, `unavailable`, `not_applicable` and `error` with a documented reason. An exception does not convert a failing observed setting into a pass. Not applicable requires a supported applicability decision. Report definitive coverage `(pass + fail) / applicable checks` separately from observed pass rate `pass / (pass + fail)`; no definitive results means no pass rate. Neither metric represents CIS certification or full tenant compliance.

Compare only compatible customer, scope, checklist/evaluator versions and evidence sources. Separate observed configuration drift, role/account changes, coverage changes and baseline changes. A missing user after a partial page fetch is not a confirmed removal. Expired/manual evidence and API loss are coverage changes, not configuration regressions. Deduplicate notices by saved comparison identity. Retain the last completed report alongside a newer failed/running attempt and display both dates.

Proposed cadence for later implementation: daily bounded API snapshots, a weekly review digest, monthly manual-policy review, and a new review after significant admin/policy changes. Make cadence, evidence retention and recipients workspace-configurable. Event-only collection cannot detect every current policy change. No automation or outbound notification is enabled by this document.

## Implementation and validation gates

- [ ] Review and pin the exact Workspace Benchmark version/profile, usage rights, applicable safeguards and Google edition/population before publishing the baseline.
- [x] Implement workspace-scoped encrypted connection storage, dedicated OAuth configuration inputs, connect/validation/health/disconnect routes; actual Cloud project configuration and consent remain pending.
- [ ] Prove consent cancellation, missing/extra grants, expired/replayed state, wrong customer/domain, lost roles and invalid refresh grants fail safely.
- [ ] Exercise primary/secondary/alias domains and customer-wide policies without cross-workspace disclosure. Prove unauthorized users cannot connect, collect or download another workspace's evidence.
- [ ] Implement bounded paginated collectors with allowlisted read methods/endpoints and selected fields. Validate partial pages, quota errors, event latency and edition gaps without false passes.
- [x] Implement the checklist and append-only manual evidence with policy scope, proposed target, rationale, owner and validation; real policy evidence and reviewed benchmark procedures remain pending.
- [ ] Validate first/repeat/drift assessments: unchanged results create no duplicate drift notice; settings, scope, baseline and coverage changes remain distinct.
- [ ] Add dashboard topic, overview, saved JSON/PDF section and report-library integration. Review populated desktop/mobile and keyboard flows and render the appended PDF without altering prior report sections.
- [ ] Validate a real consenting test-domain administrator, scheduled token refresh, privilege loss/reconnect and disconnect. Confirm no configuration writes and keep tenant validation receipts private.
- [ ] Enable the agreed workspace schedule and reporting recipients only after live acceptance. Record the first successful assessment, repeat comparison and delivery evidence in integration readiness.

Ongoing project reports should describe the feature as **implemented locally / no live tenant assessment**. Production activation, benchmark pinning, real consent, customer scope/privilege validation and scheduled-operation acceptance remain open.


## CSP and BFS rollout checklist

1. Create a dedicated Google Cloud project for the Admin audit integration, separate from the portal login/Drive project, and enable the Admin SDK API. Use an external OAuth audience for access by both independent customer organizations. For a limited pilot, explicitly add the authorized CSP and BFS admin accounts as test users; complete Google's required verification/publication work before broader use. Testing-mode token lifetime limits must not be treated as production schedule acceptance.
2. Configure app branding/support contact, authorized domains and a Web application OAuth client. Register the production redirect URI exactly as `https://daedalus.cybersecuritypilot.org/auth/google-admin/callback`. If a local consent rehearsal is needed, register its exact loopback callback separately. Request only the initial scope manifest listed above.
3. Install `GOOGLE_ADMIN_CLIENT_ID` and `GOOGLE_ADMIN_CLIENT_SECRET` in the server's protected production environment. Retain the existing integration encryption key; changing that key would invalidate stored integration credentials. Do not paste the client secret into chat or commit it. The application rejects reusing the login client ID; the operator must also verify that it belongs to a separate Cloud project, since a different client ID alone does not prove project separation.
4. Activate the tested source through the existing Incus backup/release/readiness workflow. Do not disable ownership validation or populate production with synthetic preview data.
5. Confirm current CSP and BFS workspace membership and domain ownership independently. For a workspace with pending ownership, use its normal TXT verification workflow; the Google audit connector deliberately requires verified status and does not substitute a probation override.
6. In CSP's Google Admin security topic, review the entire-customer scope acknowledgment, connect the authorized Google audit administrator and complete consent. Validate the returned customer ID/domains against the intended organization. Repeat separately in BFS. If both domains actually belong to one Workspace customer, stop and agree the customer-wide sharing/workspace model rather than bypassing the duplicate-customer guard.
7. Run the first audit in each workspace, review definitive checks and manual/privilege gaps, and download/render its PDF and JSON. Record consent/customer-binding and collection receipts privately. Add effective-policy evidence with its actual capture time. Establish the reviewed Workspace Benchmark version/rights before upgrading configuration-specific baseline claims.
8. Repeat each audit; confirm comparison isolation, unchanged-result notice suppression, failures and reconnect behavior. Review the saved report/coverage and explicitly opt into the desired recurrence. Validate an actual scheduled refresh and inbox notice. Keep outbound email delivery as a separate requirement.

Google setup references: [OAuth consent/audience](https://developers.google.com/workspace/guides/configure-oauth-consent), [web-server consent and offline access](https://developers.google.com/identity/protocols/oauth2/web-server), and [Directory scope documentation](https://developers.google.com/workspace/admin/directory/v1/guides/authorizing).
