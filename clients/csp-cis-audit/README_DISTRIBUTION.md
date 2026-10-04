# CSP CIS client distribution guide

This guide describes the current Xcode menu-bar app. The older SwiftPM and LaunchDaemon material has been retired; the app reads a per-user Daedalus config and must run as that user.

## Build

The Xcode project minimum deployment target is macOS 15.4. Build the `CSP-CIS_Audit` scheme in Xcode and archive it for distribution. For a local unsigned build only:

```bash
xcodebuild -project CSP-CIS_Audit.xcodeproj -scheme CSP-CIS_Audit -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO build
```

For direct distribution, use `./scripts/build-notarized-client.sh [output-directory]`. It selects the only available Developer ID Application identity or accepts `CSP_CIS_SIGNING_IDENTITY`, derives and checks `CSP_CIS_TEAM_ID`, archives with hardened runtime, submits through the `notarytool` keychain profile named by `CSP_CIS_NOTARY_PROFILE` (default `daedalus-cis-notary`), staples the ticket, and requires `spctl` to accept the app before writing the final ZIP. The script refuses to build without a Developer ID identity. It does not disable Gatekeeper or ask users to override it. Never put signing keys or notarization credentials in this repository or the app archive. Confirm the app launches and uploads a test report on each supported macOS version before deploying broadly. A signed MDM package build workflow is available below; signed package installation and update acceptance remain unverified until the required certificates are available. Users can opt into launch at login from the app menu. Once open, the menu-bar app checks in at launch, on demand, and every 24 hours.

Do not run the menu-bar app with `sudo`, deploy the legacy LaunchDaemon, or run it as a shared root service. Each endpoint needs a per-user config and private device identity. The app checks at launch, every 24 hours while open, and when the user selects **Run Checks**.

## MDM installer package

First build the notarized app with `scripts/build-notarized-client.sh`. Then run:

```bash
./scripts/build-mdm-package.sh /absolute/path/CSP-CIS_Audit.app /absolute/path/new-package-output
```

The package workflow requires a valid Developer ID Application signature and stapled app ticket, plus a Developer ID Installer identity from the same team. Set `CSP_CIS_INSTALLER_IDENTITY` when multiple installer identities exist. It uses the existing `CSP_CIS_NOTARY_PROFILE` keychain profile, submits the signed package for notarization, staples its ticket and requires Gatekeeper's install assessment before writing the final checksum. Apple's [installer signing guidance](https://help.apple.com/xcode/mac/current/en.lproj/deve51ce7c3d.html) describes the separate Installer certificate.

The credential-free payload installs only `CSP-CIS_Audit.app` under `/Applications`; relocation to older copies elsewhere is disabled. There are no install scripts, root collection service or bundled workspace config. Installation does not launch the app, import a config or register a login item. Existing per-user Daedalus configs, identity and reports remain outside the payload. Deploy the package through your MDM, then complete per-user configuration and launch-at-login setup described below. Validate fresh install, update, removal and user login on macOS 26 before broad deployment; this workflow has not yet produced an accepted signed package in this environment.

## Local artifact

Run `./scripts/build-local-client.sh` from this repository to create a Release build, ad hoc signed ZIP, and SHA-256 checksum in a new timestamped `dist/local-client-*` directory. An optional first argument selects a new output directory. The script refuses an existing destination and checks that workspace config files were not bundled. It does not install, launch, register a login item, run an audit, or upload anything. It builds for the current Mac architecture; a production archive is built for the generic macOS destination.

The ad hoc signed local ZIP validates bundle integrity but has no trusted publisher identity; Gatekeeper can still reject it. Use the notarized release script for external distribution. No certificate, upload key, or notarization credential belongs in either script or artifact.

## Launch at login

After installing the signed app in Applications and importing the private config, choose **Enable Launch at Login** from the CSP menu. This uses Apple's `SMAppService.mainApp` registration and applies to the current user. The menu displays **enabled**, **off**, **approval required**, or **app unavailable**, and refreshes that status when reopened.

When approval is required, select **Open Login Items Settings…** and approve the app in System Settings. **Disable Launch at Login** unregisters the app, including a pending approval request. These actions occur only when the user selects them. The app audits at launch and every 24 hours while open; closing it or logging out pauses that schedule. Login registration does not provide unattended collection while logged out.

Apple documents the registration and approval model in [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice).

## Workspace setup

1. In the workspace **CIS profiles** tab, publish the macOS 26 Level 1 and Level 2 profiles or the legacy CSP profile. The Tahoe profiles are derived from the pinned NIST mSCP Revision 3 baseline, but only a limited set of their rules map to local CSP checks. Unsupported rules are marked manual. Their pass rate is not a CIS attestation.
2. In **Client profile**, select the profile for the deployment, or leave it on the newest compatible macOS profile.
3. Select **Issue client key and download config**. The one-time YAML download contains a workspace upload key. If rotating the key, replace the config on every deployed client; the previous key stops working.
4. In the CSP CIS menu-bar app, choose **Import Daedalus client config…** and select the YAML file. The app copies it to `~/Library/Application Support/Daedalus/cis-client.yaml` and applies owner-only file permissions.
5. Run **Run Checks** and confirm the new endpoint report appears in the Daedalus workspace with the expected profile, check counts, and pass rate.

Never put an upload key in the app bundle, installer, repository, shared image, or public download. Daedalus stores a hash of the key; the original is only in the one-time download and each imported user copy. If key delivery through MDM is added, deliver a unique user-scoped config through a private channel.

## Reports and data

The client stores JSON/text reports and run logs under `~/Library/Application Support/Daedalus/CIS Client/` in private subdirectories. A persistent random UUID identifies the endpoint across reports; hardware serial numbers are not collected. Daedalus stores normalized results, the profile slug/version, score, and changes between reports. The dashboard labels the percentage as a pass rate; fail, manual, and error checks remain in its denominator.

The client uploads check results, device name, OS version, anonymous device ID, and report timestamps over HTTPS. The server removes details it does not need and scrubs common identifiers from check evidence. Review the profile's result details and workspace privacy requirements before deployment.

If a configured upload fails, the private JSON remains queued locally. The client retries saved reports at launch and periodically while open; **Retry saved reports** requests a retry without running new checks. Reports retain their original IDs and timestamps. Confirm a later successful retry creates one workspace report, and rotate/reimport the workspace key if access was revoked.

## Updating profiles

Published profile versions are immutable. Upload a revised profile JSON and choose a new version to preserve historical comparisons. The Tahoe profiles include source attribution and the CC BY 4.0 license notice for NIST mSCP material. Validate each automated rule against the CIS benchmark and macOS 26 before using the pass rate as evidence of benchmark conformance.

## Validation before rollout

- Build and run the app as a standard user on each macOS release in scope.
- Confirm the imported config is private and the workspace upload key can be rotated/revoked.
- Confirm a report identifies the expected endpoint and profile version, and that the dashboard shows pass/fail/manual/error counts.
- Confirm a later run creates the expected check-status history.
- Review manual/unsupported checks; do not interpret those as passes.
- Confirm install/update, login registration, approval, and removal with a signed app and the target MDM before broad deployment. macOS 26 runtime validation is still required; compiling against its SDK does not verify managed preference behavior.

## Offline report delivery

Reports are saved before upload. The client retries unacknowledged JSON reports at launch, every 15 minutes while open, and through **Retry saved reports** (up to ten matching-workspace reports per batch). It retains the original report ID so server retries are idempotent. A private `.uploaded` receipt is written only when Daedalus returns an explicit acceptance response. Reports from another workspace are skipped after importing a different domain's config. Invalid/rejected reports remain saved for review; they are never silently deleted. Upload and profile requests reject redirects to another origin or an HTTPS downgrade.
