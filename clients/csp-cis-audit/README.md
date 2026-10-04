# CSP - CIS Compliance Scanner

A macOS menu-bar client that runs endpoint checks locally, stores a JSON and text report, and can upload results to a Daedalus workspace. The maintained app target is `CSP-CIS_Audit.xcodeproj` / `CSP-CIS_Audit`.

## Current status

The bundled CSP profile is version `1.0.0`: 98 macOS checks, 33 Chrome checks, and 23 Safari checks. Its IDs are list-position IDs, and it has not been mapped to official CIS recommendation IDs. Treat the displayed percentage as a pass rate for this CSP checklist, not as CIS certification or a macOS 26 benchmark score. See [CIS-MACOS26-ALIGNMENT.md](CIS-MACOS26-ALIGNMENT.md).

The app runs checks at launch, when **Run Checks** is selected, and every 24 hours while the menu-bar app remains open. Each completed run uploads a report when a valid Daedalus config is installed. The app offers opt-in launch at login; a signed/notarized MDM deployment package remains pending.

## Build and run

The Xcode project minimum deployment target is macOS 15.4. This is the app's OS compatibility setting; it does not mean the bundled checks have been validated against the macOS 26 benchmark. Open the project in Xcode and build the `CSP-CIS_Audit` scheme, or run:

```bash
xcodebuild -project CSP-CIS_Audit.xcodeproj -scheme CSP-CIS_Audit -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO build
```

Run the signed app as the logged-in user. Do not run it with `sudo` or install the legacy LaunchDaemon: the client config and its report identity are private to that user.

## Connect to Daedalus

In the workspace's **CIS profiles** tab, choose a compatible client profile from the **Client profile** dropdown, then issue/download the config. In the CSP CIS menu-bar app, select **Import Daedalus client config…** and choose that file. The app stores its copy at `~/Library/Application Support/Daedalus/cis-client.yaml` with owner-only permissions.

A revocable user access key from Daedalus **Access keys** can also be used as the `api_key` in the private client config. It binds uploads and profile downloads to its workspace and stops working when it expires, is revoked, or the user loses approved membership. This avoids rotating the shared workspace deployment key. Give an endpoint its own named key and plan renewal before its expiry. User access keys also permit dashboard/API access under the owning user’s current role; keep them private.

Keep the workspace API key private. Do not bundle it in the app, put it in an installer, commit it, or distribute it through a public link. Daedalus stores a hash of the upload key and supports rotation or revocation.

At each run the client downloads the selected published profile. A blank profile selection uses the newest compatible macOS profile. If a profile slug was explicitly selected and the portal cannot provide that profile, the client skips the run rather than silently switching to the bundled CSP baseline. With no selected profile, an unavailable portal still uses the bundled CSP checklist.

## Checks and reports

Checks run on the Mac. The Daedalus catalog includes CIS macOS 26 Tahoe Level 1 and Level 2 profiles derived from the pinned NIST mSCP Tahoe Revision 3 baseline. The CSP client implements 94 stable mSCP rule IDs as bundled read-only checks: 44 preference checks, 40 fixed-command checks, one audit-policy check, and 9 bounded audit filesystem/ACL checks. The nine audit checks cover audit-file and audit-folder owner, group, mode, and ACL controls plus the audit-control ACL; all nine occur in each profile. Six Safari rules inspect the pinned settings in installed configuration profiles and the SMB guest-access check uses a fixed read-only `sysadminctl` query. Unimplemented rules are reported as `manual`, and Tahoe profile checks run only on macOS 26. Audit checks inspect metadata only and never upload audit-log file names or contents; profile output is parsed locally and not copied into reports. The client covers 87 Level 1 and 92 Level 2 profile checks; 13 Level 1 and 27 Level 2 checks remain manual. The percentage is `passed / total checks × 100`, with fail, manual, and error results in the denominator. It is a pass rate, not a CIS attestation. See [CIS-MACOS26-ALIGNMENT.md](CIS-MACOS26-ALIGNMENT.md) for source and implementation status.

Each report uses a persistent random device UUID saved with owner-only permissions. The client does not collect hardware serial numbers. Reports and run logs are stored under `~/Library/Application Support/Daedalus/CIS Client/` in private subdirectories.

The client uploads check results, device name, macOS version, and the stable anonymous ID to Daedalus over HTTPS. The server normalizes the submitted report before storing it. Check details can include local configuration evidence, so review them before distributing this client.

## Legacy files

The retired developer-specific LaunchDaemon plist has been removed. Use the per-user menu-bar app and its launch-at-login option; the signed MDM package workflow is documented in README_DISTRIBUTION.md.

### Separate client check-ins

The updated menu-bar client sends a same-origin authenticated check-in at launch and every five minutes while open. The server accepts it only after the first report has registered this device in the key's workspace. Check-ins carry the private stable device identifier, never check results or a score, and do not update report timestamps. The dashboard marks client presence overdue after 15 minutes without a check-in. Older clients remain presence-unknown even when they have a recent report. Audits still run at launch, on demand and every 24 hours while open; this does not install a background daemon or provide trusted signing/notarization.

Legacy minimum password age reads `pwpolicy -getglobalpolicy` through the bounded command collector. It accepts an explicit canonical integer `minMinutesUntilChangePassword` only, compares minutes directly with the existing 1440-minute criterion, rejects duplicate or malformed fields and failed reads, and leaves absent evidence manual. The result describes the captured deprecated legacy field; it does not prove modern account-policy or directory enforcement. The field's minutes-between-changes semantics are defined in the [OVAL macOS schema](https://github.com/OVAL-Community/OVAL/blob/master/guidelines/oval-schema-documentation/macos-definitions-schema.rst). This change does not add a Tahoe benchmark rule or change published profile thresholds.

The legacy login-keychain sleep-lock check uses a bounded read of the current user's explicit login.keychain-db path. It recognizes Apple's settings-line format on stdout or stderr, requires a successful exit and exact path, and evaluates the `lock-on-sleep` flag independently from timeout settings. Failed reads, mixed output/error messages and unsupported settings remain manual. No keychain contents, account paths or credentials are included in the reported details. This captures one user's settings rather than demonstrating live sleep/unlock behavior. Output semantics follow [Apple's security tool source](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/keychain_show_info.c).

Legacy file-permission checks read the modes of all matching entries in the existing `/Users` scope with fixed `find` and `stat` arguments. Any permission bit outside the legacy allowed mask fails; special mode bits also fail. No matching entries, malformed or oversized output, permission errors, nonzero exits and bounded-read failures remain manual. Results describe captured mode bits only, not ACLs, ownership, other home-directory locations or subsequent filesystem changes. Paths are not copied into report details. Published Tahoe profiles and their supported-rule counts are unchanged.

Legacy password complexity uses the same strict bounded global-policy parser as minimum age. It requires canonical `0` or `1` values for all four legacy fields (`requiresAlpha`, `requiresNumeric`, `requiresSymbol`, `requiresMixedCase`) and applies the existing criterion of at least three distinct enabled fields. Duplicate keywords and overlapping text patterns cannot increase the count. Missing, malformed or failed evidence remains manual. This is a legacy configuration observation, not evaluation of modern account-policy predicates, directory enforcement or actual password acceptance.

The stricter legacy Gatekeeper check uses bounded `spctl --status` evidence and a typed `AllowIdentifiedDevelopers` system-policy preference. It no longer invokes `spctl --list` or waits on unread rule output. Enabled assessments alone cannot establish the stricter policy. Missing preferences, failed status reads or unsupported output remain manual; collected App Store-only settings do not constitute a live application acceptance test or inspection of all exceptions. Setting semantics follow [Apple's SystemPolicyControl documentation](https://developer.apple.com/documentation/devicemanagement/systempolicycontrol).

The legacy software-current check uses a bounded read-only Software Update query and exact recognized response lines. A successful no-updates response describes current catalog availability rather than every installed application's patch state. Offered update labels fail the legacy check; unavailable, malformed, contradictory or failed queries remain manual. Raw update output is not included in reported details and no installation is performed.

### Configured check timeouts

Timeout values in `timeouts` and per-check overrides must be finite numbers from 0.1 through 300 seconds. Invalid values retain the category default or omit the per-check override. Defaults are 10 seconds for ordinary checks, 30 for filesystem checks and 20 for network checks. This bounds the client wait; supported command collectors also apply their own deadlines.
