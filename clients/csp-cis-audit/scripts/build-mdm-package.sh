#!/bin/bash
# Package an already notarized client; never install, launch or enroll users.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo 'Usage: build-mdm-package.sh notarized-app-path new-output-directory' >&2
    exit 2
fi
csp_app="$1"
csp_output="$2"
[[ -d "$csp_app" && "$(basename "$csp_app")" == CSP-CIS_Audit.app ]] || { echo 'Expected CSP-CIS_Audit.app directory.' >&2; exit 2; }
[[ ! -e "$csp_output" ]] || { echo 'Output directory already exists.' >&2; exit 2; }
for csp_tool in codesign security xcrun spctl pkgbuild productsign pkgutil ditto shasum; do
    command -v "$csp_tool" >/dev/null || { echo "Required macOS tool not found: $csp_tool" >&2; exit 2; }
done
if [[ -n "$(find "$csp_app" -type f \( -iname config.yaml -o -iname cis-client.yaml -o -iname cis-client.yml \) -print -quit)" ]]; then
    echo 'Refusing app containing workspace configuration.' >&2; exit 2
fi
codesign --verify --deep --strict "$csp_app"
csp_signature="$(codesign -dv --verbose=2 "$csp_app" 2>&1)"
[[ "$csp_signature" == *'Authority=Developer ID Application:'* ]] || { echo 'A Developer ID Application signature is required.' >&2; exit 2; }
csp_team="$(printf '%s\n' "$csp_signature" | sed -nE 's/^TeamIdentifier=([A-Z0-9]{10})$/\1/p')"
[[ -n "$csp_team" ]] || { echo 'Missing application signing team.' >&2; exit 2; }
xcrun stapler validate "$csp_app"
spctl --assess --type execute --verbose=2 "$csp_app"
csp_identities="$(security find-identity -v 2>/dev/null | sed -nE 's/.*"([^\"]*Developer ID Installer:[^\"]*)".*/\1/p')"
csp_identity="${CSP_CIS_INSTALLER_IDENTITY:-}"
if [[ -z "$csp_identity" ]]; then
    [[ "$(printf '%s\n' "$csp_identities" | sed '/^$/d' | wc -l | tr -d ' ')" == 1 ]] || { echo 'Select a valid Developer ID Installer identity with CSP_CIS_INSTALLER_IDENTITY.' >&2; exit 2; }
    csp_identity="$csp_identities"
fi
printf '%s\n' "$csp_identities" | grep -Fqx -- "$csp_identity" || { echo 'Selected installer identity is unavailable.' >&2; exit 2; }
[[ "$csp_identity" == *"($csp_team)" ]] || { echo 'Installer and application signing teams must match.' >&2; exit 2; }
mkdir -p "$csp_output"
csp_output="$(cd "$csp_output" && pwd)"
csp_stage="$(mktemp -d "$csp_output/.package-stage.XXXXXX")"
trap 'rm -rf "$csp_stage"' EXIT
mkdir "$csp_stage/Applications"
ditto "$csp_app" "$csp_stage/Applications/CSP-CIS_Audit.app"
# Component metadata explicitly disables relocation to older copies elsewhere.
pkgbuild --analyze --root "$csp_stage" "$csp_output/components.plist"
/usr/libexec/PlistBuddy -c 'Set :0:BundleIsRelocatable false' "$csp_output/components.plist"
pkgbuild --root "$csp_stage" --component-plist "$csp_output/components.plist" --identifier org.cybersecuritypilot.daedalus.cis-client --install-location / "$csp_output/client-unsigned.pkg"
csp_package="$csp_output/CSP-CIS_Audit-macOS.pkg"
productsign --sign "$csp_identity" --timestamp "$csp_output/client-unsigned.pkg" "$csp_package"
pkgutil --check-signature "$csp_package"
xcrun notarytool submit "$csp_package" --keychain-profile "${CSP_CIS_NOTARY_PROFILE:-daedalus-cis-notary}" --wait
xcrun stapler staple "$csp_package"
xcrun stapler validate "$csp_package"
spctl --assess --type install --verbose=2 "$csp_package"
(cd "$csp_output" && shasum -a 256 CSP-CIS_Audit-macOS.pkg > SHA256SUMS)
rm "$csp_output/client-unsigned.pkg" "$csp_output/components.plist"
printf 'Signed notarized installer verified: %s\n' "$csp_package"
