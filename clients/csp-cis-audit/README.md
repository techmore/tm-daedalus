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

Checks run on the Mac. The Daedalus catalog includes CIS macOS 26 Tahoe Level 1 and Level 2 profiles derived from the pinned NIST mSCP Tahoe Revision 3 baseline. The CSP client implements 89 stable mSCP rule IDs as bundled read-only checks: 44 preference checks, 35 fixed-command checks, one audit-policy check, and 9 bounded audit filesystem/ACL checks. The nine audit checks cover audit-file and audit-folder owner, group, mode, and ACL controls plus the audit-control ACL; all nine occur in each profile. Six Safari rules inspect the pinned settings in installed configuration profiles and the SMB guest-access check uses a fixed read-only `sysadminctl` query. Unimplemented rules are reported as `manual`, and Tahoe profile checks run only on macOS 26. Audit checks inspect metadata only and never upload audit-log file names or contents; profile output is parsed locally and not copied into reports. The client covers 82 Level 1 and 87 Level 2 profile checks; 18 Level 1 and 32 Level 2 checks remain manual. The percentage is `passed / total checks × 100`, with fail, manual, and error results in the denominator. It is a pass rate, not a CIS attestation. See [CIS-MACOS26-ALIGNMENT.md](CIS-MACOS26-ALIGNMENT.md) for source and implementation status.

Each report uses a persistent random device UUID saved with owner-only permissions. The client does not collect hardware serial numbers. Reports and run logs are stored under `~/Library/Application Support/Daedalus/CIS Client/` in private subdirectories.

The client uploads check results, device name, macOS version, and the stable anonymous ID to Daedalus over HTTPS. The server normalizes the submitted report before storing it. Check details can include local configuration evidence, so review them before distributing this client.

## Legacy files

`com.csp.cis-compliance.plist` and the old SwiftPM/LaunchDaemon instructions are retained as historical files. They are not the supported distribution path for this menu-bar app.

### Separate client check-ins

The updated menu-bar client sends a same-origin authenticated check-in at launch and every five minutes while open. The server accepts it only after the first report has registered this device in the key's workspace. Check-ins carry the private stable device identifier, never check results or a score, and do not update report timestamps. The dashboard marks client presence overdue after 15 minutes without a check-in. Older clients remain presence-unknown even when they have a recent report. Audits still run at launch, on demand and every 24 hours while open; this does not install a background daemon or provide trusted signing/notarization.
