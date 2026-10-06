# CIS macOS 26 alignment

**Status:** Daedalus now has installable macOS 26 Tahoe Level 1 and Level 2 profile data. The CSP client maps 87 of the 100 Level 1 rule IDs and 92 of the 119 Level 2 rule IDs to bundled read-only checks. Mapping counts do not establish complete benchmark procedure coverage. macOS 26 CI evidence exists, but physical managed endpoint deployment and procedure-by-procedure validation remain outstanding; results remain CSP pass rates, not CIS attestations.

## Source and attribution

The profile JSON files are derived from the NIST macOS Security Compliance Project (mSCP) Tahoe Guidance Revision 3, pinned at commit `beceac1d21baf9d924c2780f2e248577435bbfb1`. That release identifies the CIS Apple macOS 26.0 Tahoe Benchmark v1.1.0 Level 1 and Level 2 baselines.

- [NIST mSCP macOS security guidance](https://pages.nist.gov/macos_security/)
- [Pinned Tahoe Revision 3 baseline source](https://github.com/usnistgov/macos_security/tree/beceac1d21baf9d924c2780f2e248577435bbfb1/baselines)
- [mSCP release history](https://github.com/usnistgov/macos_security/releases)
- [CIS Apple operating system benchmarks](https://www.cisecurity.org/benchmark/apple_os)
- [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/)

The generated profiles retain mSCP rule IDs, rule titles, and CIS recommendation references with attribution and a no-endorsement notice. They do not include or execute NIST shell check commands and do not copy Apple Vendor Description content. Regenerate them with `scripts/build_cis_macos26_profiles.py` and an mSCP checkout at the pinned commit.

### Upstream currency check (October 2, 2026)

The official mSCP site now announces macOS 27 support on its main branch. Its release history still lists Tahoe Guidance Revision 3 (`beceac1d21baf9d924c2780f2e248577435bbfb1`) as the latest tagged Tahoe 26 release, and that release aligns the CIS macOS 26 baseline to v1.1.0. The CSP client remains pinned to the Tahoe-specific revision; the newer macOS 27 branch is not interchangeable with the macOS 26 benchmark. This check confirms upstream baseline selection only; it does not validate local check behavior on a macOS 26 host.

- [mSCP project status and supported platforms](https://pages.nist.gov/macos_security/)
- [mSCP tagged release history](https://github.com/usnistgov/macos_security/releases)

Profile publication revision `1.1.0-r2` keeps benchmark version `1.1.0` and makes the description independent of the client build. Previously published `1.1.0` profiles remain immutable; installing the revised profiles publishes new versions. New clients pinned by slug select the latest published revision. Existing reports retain their original version.

## What the profiles report

The Daedalus **CIS profiles** tab has an admin action to publish both immutable profile versions. The **Client profile** dropdown can pin either Level 1 or Level 2 in the downloaded client configuration. The client fetches that exact profile and retains each mSCP rule ID and CIS recommendation ID in its report.

The CSP client maps 94 stable mSCP rule IDs to bundled read-only local routines: 44 preference checks, 40 command checks, one bounded audit-policy check, and 9 bounded audit filesystem/ACL checks. The Level 1 profile includes 87 mappings and Level 2 includes 92; 13 Level 1 and 27 Level 2 rules remain manual. These are implementation mappings, not a count of procedures verified on macOS 26. Boot FileVault evidence and the separate internal APFS inventory check do not cover external drives; external-volume encryption remains manual. Six Safari rules inspect only the exact managed-profile keys and values used by the pinned mSCP checks; the SMB guest-access check uses the bundled `sysadminctl` status command. The guest-folder check reads only `/Users` entry names and emits generic status details without disclosing names. Profile output is parsed locally and never copied into report details. Commands use static executables and arguments without shell or sudo, with bounded runtime and output. Audit checks parse only the bounded `dir:` setting from a no-follow read of `/etc/security/audit_control`, inspect the configured directory and its direct regular-file entries, and never collect file names or audit contents. Missing, inaccessible, malformed, ambiguous, symlink, or unsupported audit evidence remains manual; explicit metadata or ACL mismatches fail. Missing or incorrectly typed preference evidence is also reported as `manual`; explicit mismatches fail. Conflicting managed-profile values remain manual. All remaining rules, including supplemental manual checks, are reported as `manual`. The client only runs a Tahoe profile on macOS 26. If the configured profile cannot be fetched, the client skips the run rather than silently switching to the old CSP checklist.

Daedalus displays `passed / all checks × 100`; `fail`, `manual`, and `error` results remain in the denominator. Treat the percentage as an observed CSP pass rate. It is not certification, a conformance statement, or evidence that every CIS recommendation has been checked.

Reports naming a profile must match a published workspace version and its complete check set. New reports retain the endpoint name and OS version observed at collection. Change comparisons stay within the same profile and version; late queued reports are stored without backwards change alerts. Older records without endpoint snapshots cannot reconstruct their original device details.

The legacy CSP profile remains available and contains 154 checks (98 macOS, 33 Chrome, 23 Safari). Its IDs are list-position based and are not CIS recommendation IDs. Keep it separate from the Tahoe profiles when comparing report history.

## Check-in and deployment limits

The menu-bar client runs assessments at launch, on demand, and every 24 hours while it remains open. It sends a separate client heartbeat every five minutes. Daedalus considers client presence online when a nonfuture heartbeat is within 15 minutes; no heartbeat is unknown. The separate 36-hour report-recency window describes assessment freshness and does not establish that the client is running. The client offers opt-in launch at login. A signed/notarized MDM package and verified login-item deployment are still pending; an endpoint that is shut down or has the app closed will not check in.

The Xcode deployment target is macOS 15.4, which is the minimum OS for the app binary. A Tahoe profile itself requires macOS 26. The local Mac has not been used for a live Tahoe audit in this implementation pass. Unit tests and profile installation tests run on the available macOS 27.0 host; these establish fixture behavior and profile coverage, not macOS 26 runtime conformance.

## Remaining validation

1. Run the profile against a macOS 26 test endpoint and review the 87 Level 1 and 92 Level 2 implemented profile checks against the CIS v1.1.0 recommendation requirements.
2. Implement dedicated local checkers for the remaining CIS rules, with explicit outcomes for missing permissions and unsupported settings.
3. Package and sign/notarize the client, then add a supported login-start/deployment workflow.
4. Verify report upload, device presence, comparison history, and generated PDFs using a test endpoint before broad deployment.

The internal APFS encryption rule uses a bounded structured disk inventory and explicit FileVault booleans for eligible internal volumes. It follows the pinned rule's Preboot/Recovery/VM name exclusions, retains names locally, validates device identifiers and internal/APFS metadata, caps inventory at 32 volumes and stops collection after a six-second admission deadline (each command remains bounded to three seconds). Missing, duplicate, unsupported, timed-out or inaccessible evidence is manual; an explicit eligible unencrypted volume fails. Only complete captured eligible encrypted evidence passes. This does not prove real Tahoe execution.

Tahoe audit retention uses the pinned CIS `30d` policy value, separately from the legacy seven-day CSP criterion. A canonical `30d` age-only field passes; an explicit shorter age-only policy fails. Alternative durations, combined age/size conditions and unknown/duplicate/inaccessible evidence remain manual. No record-age, central-retention or actual kernel-activation evidence is inferred, and raw policy text is not uploaded.

The password-hint rule follows the pinned `dscl . -list /Users hint` enumeration, with bounded command output and a 10,000-account limit. Explicit hint content fails; a complete recognized enumeration without hint text passes. Missing, failed, duplicate or unsupported records remain manual. Account names and hint text are parsed locally and omitted from uploaded details. This covers local records returned by the directory query, not external directory policy or actual Tahoe runtime validation.

The session-owner authorization rule parses a bounded successful XML policy read for system.login.screensaver. An explicit authenticate-session-owner policy passes; authenticate-session-owner-or-admin fails. The bundled psso-screensaver and psso-screensaver-mscp references are followed once with fixed executable arguments. Multiple rule entries, duplicate decoded dictionary keys, inaccessible or unsupported policy remain manual. This is captured policy evidence, not a live unlock test, complete smartcard/PSSO applicability validation, or remediation. Authorization settings are never written.

The system-wide preference rule reads all eight fixed authorization rights from the pinned source. Each must explicitly require the admin group, authenticate-user=true, shared=false and session-owner=false with typed Boolean values. Missing, ambiguous, oversized or failed XML evidence remains manual; explicit mismatches fail. Each read is bounded and a six-second admission deadline stops further reads. These are captured authorization policies, not a live System Settings interaction test; no policy is written.

Both authorization-policy readers share a bounded XML validator before plist decoding. It rejects duplicate decoded keys within each dictionary (including character-reference and CDATA spellings), oversized key names, excessive nesting, malformed XML and internal entity declarations; external entity resolution is disabled. Equivalent valid key encoding is accepted. Repeated names in separate nested dictionaries are not treated as duplicates.

Tahoe password history parses bounded global local-account policy XML from the fixed pwpolicy -getaccountpolicies command. Every captured typed policyAttributePasswordHistoryDepth value must be at least the pinned CIS value 24; an explicit shorter depth fails. Missing, fractional, Boolean, string, negative, duplicate, unsupported or inaccessible evidence remains manual. The command output and account-policy content remain local. This assesses captured policy parameters, not a password-reuse attempt or external directory policy. The legacy CSP five-password criterion stays separate.

Tahoe minimum length uses the same bounded local account-policy XML reader. It recognizes canonical standalone policyAttributePassword matches minimum-length conditions in password-content entries and compares the strongest explicit minimum with the pinned CIS value 15. Unsupported or compound predicates, absent/malformed values, failed reads and ambiguous XML remain manual. Raw predicates remain local. This is captured policy evidence, not a password-creation attempt or a statement about external directory accounts.

Password lifetime parses explicit typed positive policyAttributeExpiresEveryNDays values from bounded account-policy XML. The longest value is compared without rounding against 365 days for Tahoe CIS and 90 days for the separate legacy CSP check. Missing, zero, negative, Boolean, string, oversized or failed evidence remains manual. Zero is not taken as proof of an enforced lifetime. Results describe captured local policy parameters and do not recommend or perform password rotation.

Account lockout checks parse typed integer policyAttributeMaximumFailedAuthentications and autoEnableInSeconds values from bounded account-policy XML. Positive attempt limits must be at most five; lockout durations must be at least 900 seconds (15 minutes). Missing, negative, fractional, Boolean, string, oversized or failed evidence remains manual. A zero attempt limit is not treated as enforced. The legacy attempt-limit check uses the same structured evidence while preserving its ID. No failed-login attempts, account locks, or policy changes are performed.

### Organization-approved login warning message

The remaining `system_settings_loginwindow_loginwindowtext_enable` rule is deliberately manual. The pinned source reads `com.apple.loginwindow/LoginwindowText` and compares it with an organization-defined approved message. A nonempty message alone cannot establish that match, and the source's example message is not organizational approval. Current profile checks and the Swift `CISCheck` model do not carry an organization-defined expected message. Completing this rule requires a validated, immutable profile parameter and exact local comparison, without uploading the warning text. It must not increase automated mapping counts until that path is implemented and validated.

Pinned procedure: https://raw.githubusercontent.com/usnistgov/macos_security/beceac1d21baf9d924c2780f2e248577435bbfb1/rules/system_settings/system_settings_loginwindow_loginwindowtext_enable.yaml
