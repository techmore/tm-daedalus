#!/bin/bash
# Build a private local demo artifact. Never installs, launches, registers, or uploads.
set -euo pipefail

csp_repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
csp_output_dir="${1:-$csp_repo_dir/dist/local-client-$(date -u +%Y%m%dT%H%M%SZ)}"
if [[ -e "$csp_output_dir" ]]; then
    echo "Output directory already exists; choose a new path: $csp_output_dir" >&2
    exit 1
fi
mkdir -p "$csp_output_dir"
csp_output_dir="$(cd "$csp_output_dir" && pwd)"

xcodebuild -quiet \
    -project "$csp_repo_dir/CSP-CIS_Audit.xcodeproj" \
    -scheme CSP-CIS_Audit \
    -configuration Release \
    -destination 'platform=macOS' \
    -derivedDataPath "$csp_output_dir/build" \
    CODE_SIGNING_ALLOWED=NO build

csp_app_path="$csp_output_dir/build/Build/Products/Release/CSP-CIS_Audit.app"
if [[ ! -d "$csp_app_path" ]]; then
    echo "Expected app was not produced." >&2
    exit 1
fi
# Refuse accidental workspace configuration in the public app artifact, without
# opening the configuration or printing its contents.
if [[ -n "$(find "$csp_app_path" -type f \
    \( -iname 'config.yaml' -o -iname 'cis-client.yaml' -o -iname 'cis-client.yml' \) -print -quit)" ]]; then
    echo "Refusing artifact: a workspace config file was included in the app." >&2
    exit 1
fi

# With signing disabled, Xcode may leave only a linker signature on the main
# executable. Seal the full app bundle so local integrity verification works.
# This ad hoc signature carries no publisher identity and is not notarized.
codesign --force --deep --sign - --timestamp=none "$csp_app_path"
codesign --verify --deep --strict "$csp_app_path"

ditto -c -k --sequesterRsrc --keepParent "$csp_app_path" "$csp_output_dir/CSP-CIS_Audit-local-demo.zip"
(cd "$csp_output_dir" && shasum -a 256 CSP-CIS_Audit-local-demo.zip > SHA256SUMS)
cat > "$csp_output_dir/LOCAL-DEMO.txt" <<'NOTICE'
CSP CIS local demonstration artifact (ad hoc signed, not notarized).
No credentials are bundled. Import a private Daedalus config in the app.
Built for the local Mac architecture. This script has not installed or launched it.
The ad hoc signature validates bundle contents but does not establish publisher identity.
Downloaded copies may not pass Gatekeeper; do not ask end users to override that protection.
For external distribution, use a Developer ID signed and notarized archive.
Opening the app runs its audit and check-in logic with the imported user config.
Launch at login is an explicit user choice in the menu and may require approval.
NOTICE
printf 'Local artifact created: %s\n' "$csp_output_dir/CSP-CIS_Audit-local-demo.zip"
