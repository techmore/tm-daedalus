# CIS macOS 26 alignment

**Status:** Daedalus now has installable macOS 26 Tahoe Level 1 and Level 2 profile data. The CSP client implements 77 of the 100 Level 1 rules and 82 of the 119 Level 2 rules using bundled read-only checks. Those routines have not yet been validated on macOS 26, so the result remains a CSP pass rate, not a CIS attestation.

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

The CSP client implements 84 stable mSCP rule IDs as bundled read-only local checks: 44 preference checks, 31 fixed-command checks, and 9 bounded audit filesystem/ACL checks. The Level 1 profile includes 77 implementations and Level 2 includes 82; 23 Level 1 and 37 Level 2 rules remain manual. The nine audit evidence IDs are `audit_files_owner_configure`, `audit_files_group_configure`, `audit_files_mode_configure`, `audit_folder_owner_configure`, `audit_folder_group_configure`, `audit_folders_mode_configure`, `audit_acls_files_configure`, `audit_acls_folders_configure`, and `audit_control_acls_configure`. All nine occur in both profiles. Six Safari rules inspect only the exact managed-profile keys and values used by the pinned mSCP checks; the SMB guest-access check uses the bundled `sysadminctl` status command. The guest-folder check reads only `/Users` entry names and emits generic status details without disclosing names. Profile output is parsed locally and never copied into report details. Commands use static executables and arguments without shell or sudo, with bounded runtime and output. Audit checks parse only the bounded `dir:` setting from a no-follow read of `/etc/security/audit_control`, inspect the configured directory and its direct regular-file entries, and never collect file names or audit contents. Missing, inaccessible, malformed, ambiguous, symlink, or unsupported audit evidence remains manual; explicit metadata or ACL mismatches fail. Missing or incorrectly typed preference evidence is also reported as `manual`; explicit mismatches fail. Conflicting managed-profile values remain manual. All remaining rules, including supplemental manual checks, are reported as `manual`. The client only runs a Tahoe profile on macOS 26. If the configured profile cannot be fetched, the client skips the run rather than silently switching to the old CSP checklist.

Daedalus displays `passed / all checks × 100`; `fail`, `manual`, and `error` results remain in the denominator. Treat the percentage as an observed CSP pass rate. It is not certification, a conformance statement, or evidence that every CIS recommendation has been checked.

Reports naming a profile must match a published workspace version and its complete check set. New reports retain the endpoint name and OS version observed at collection. Change comparisons stay within the same profile and version; late queued reports are stored without backwards change alerts. Older records without endpoint snapshots cannot reconstruct their original device details.

The legacy CSP profile remains available and contains 154 checks (98 macOS, 33 Chrome, 23 Safari). Its IDs are list-position based and are not CIS recommendation IDs. Keep it separate from the Tahoe profiles when comparing report history.

## Check-in and deployment limits

The menu-bar client runs at launch, on demand, and every 24 hours while it remains open. Daedalus marks a device online for 36 hours after its latest report. The client offers opt-in launch at login. A signed/notarized MDM package and verified login-item deployment are still pending; an endpoint that is shut down or has the app closed will not check in.

The Xcode deployment target is macOS 15.4, which is the minimum OS for the app binary. A Tahoe profile itself requires macOS 26. The local Mac has not been used for a live Tahoe audit in this implementation pass. Unit tests and profile installation tests run on the available macOS 27.0 host; these establish fixture behavior and profile coverage, not macOS 26 runtime conformance.

## Remaining validation

1. Run the profile against a macOS 26 test endpoint and review the 77 Level 1 and 82 Level 2 implemented profile checks against the CIS v1.1.0 recommendation requirements.
2. Implement dedicated local checkers for the remaining CIS rules, with explicit outcomes for missing permissions and unsupported settings.
3. Package and sign/notarize the client, then add a supported login-start/deployment workflow.
4. Verify report upload, device presence, comparison history, and generated PDFs using a test endpoint before broad deployment.
