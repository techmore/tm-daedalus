#!/bin/bash
# Build and verify a Developer ID signed, notarized macOS client release.
set -euo pipefail

csp_repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
csp_output_dir="${1:-$csp_repo_dir/dist/notarized-client-$(date -u +%Y%m%dT%H%M%SZ)}"
csp_project="$csp_repo_dir/CSP-CIS_Audit.xcodeproj"
csp_scheme="CSP-CIS_Audit"
csp_notary_profile="${CSP_CIS_NOTARY_PROFILE:-daedalus-cis-notary}"

for csp_tool in xcodebuild codesign security xcrun ditto shasum spctl; do
    if ! command -v "$csp_tool" >/dev/null 2>&1; then
        echo "Required macOS tool not found: $csp_tool" >&2
        exit 1
    fi
done

if [[ -e "$csp_output_dir" ]]; then
    echo "Output directory already exists; choose a new path: $csp_output_dir" >&2
    exit 1
fi

csp_identities="$(security find-identity -v -p codesigning 2>/dev/null | sed -nE 's/.*"([^\"]*Developer ID Application:[^\"]*)".*/\1/p')"
if [[ -z "$csp_identities" ]]; then
    echo "No valid Developer ID Application identity is installed. Refusing to build an app that requires Gatekeeper overrides." >&2
    exit 2
fi

csp_identity="${CSP_CIS_SIGNING_IDENTITY:-}"
if [[ -z "$csp_identity" ]]; then
    csp_identity_count="$(printf '%s\n' "$csp_identities" | sed '/^$/d' | wc -l | tr -d ' ')"
    if [[ "$csp_identity_count" != "1" ]]; then
        echo "Found multiple Developer ID Application identities; set CSP_CIS_SIGNING_IDENTITY to select one." >&2
        exit 2
    fi
    csp_identity="$csp_identities"
fi

if ! printf '%s\n' "$csp_identities" | grep -Fqx -- "$csp_identity"; then
    echo "Selected signing identity is not a valid Developer ID Application identity." >&2
    exit 2
fi

csp_derived_team="$(printf '%s\n' "$csp_identity" | sed -nE 's/.*\(([A-Z0-9]{10})\)$/\1/p')"
csp_team_id="${CSP_CIS_TEAM_ID:-$csp_derived_team}"
if [[ -z "$csp_team_id" || "$csp_team_id" != "$csp_derived_team" ]]; then
    echo "CSP_CIS_TEAM_ID must match the selected Developer ID identity's team." >&2
    exit 2
fi

mkdir -p "$csp_output_dir"
csp_output_dir="$(cd "$csp_output_dir" && pwd)"
csp_archive="$csp_output_dir/CSP-CIS_Audit.xcarchive"

xcodebuild \
    -project "$csp_project" \
    -scheme "$csp_scheme" \
    -configuration Release \
    -destination 'generic/platform=macOS' \
    -archivePath "$csp_archive" \
    CODE_SIGNING_ALLOWED=YES \
    CODE_SIGN_STYLE=Manual \
    CODE_SIGN_IDENTITY="$csp_identity" \
    DEVELOPMENT_TEAM="$csp_team_id" \
    ENABLE_HARDENED_RUNTIME=YES \
    archive

csp_app_path="$csp_archive/Products/Applications/CSP-CIS_Audit.app"
if [[ ! -d "$csp_app_path" ]]; then
    echo "Expected archived app was not produced." >&2
    exit 1
fi

if [[ -n "$(find "$csp_app_path" -type f \
    \( -iname 'config.yaml' -o -iname 'cis-client.yaml' -o -iname 'cis-client.yml' \) -print -quit)" ]]; then
    echo "Refusing artifact: a workspace config file was included in the app." >&2
    exit 1
fi

codesign --verify --deep --strict "$csp_app_path"
if ! codesign -dv --verbose=2 "$csp_app_path" 2>&1 | grep -Fq "TeamIdentifier=$csp_team_id"; then
    echo "Archived app signature does not match the selected Developer ID team." >&2
    exit 1
fi

csp_submission="$csp_output_dir/CSP-CIS_Audit-notary-submission.zip"
ditto -c -k --sequesterRsrc --keepParent "$csp_app_path" "$csp_submission"
xcrun notarytool submit "$csp_submission" --keychain-profile "$csp_notary_profile" --wait

xcrun stapler staple "$csp_app_path"
xcrun stapler validate "$csp_app_path"
codesign --verify --deep --strict "$csp_app_path"
spctl --assess --type execute --verbose=2 "$csp_app_path"

csp_release_zip="$csp_output_dir/CSP-CIS_Audit-macOS-notarized.zip"
ditto -c -k --sequesterRsrc --keepParent "$csp_app_path" "$csp_release_zip"
(cd "$csp_output_dir" && shasum -a 256 "$(basename "$csp_release_zip")" > SHA256SUMS)
rm -f "$csp_submission"

printf 'Notarized app verified by Gatekeeper: %s\n' "$csp_release_zip"
