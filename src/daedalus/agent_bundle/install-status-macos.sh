#!/bin/sh
set -eu
umask 077
[ "$(uname -s)" = Darwin ] || { echo 'This indicator requires macOS.' >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
xcrun --find swiftc >/dev/null
TASK_APP="$HOME/Applications/Daedalus Scanner Status.app"
TASK_LABEL=org.daedalus.scanner-status
TASK_PLIST="$HOME/Library/LaunchAgents/$TASK_LABEL.plist"
for p in "$HOME/Applications" "$TASK_APP" "$TASK_APP/Contents" "$TASK_APP/Contents/MacOS" "$TASK_APP/Contents/MacOS/DaedalusScannerStatus" "$TASK_APP/Contents/Info.plist" "$HOME/Library/LaunchAgents" "$TASK_PLIST"; do
 [ ! -L "$p" ] || { echo 'Refusing installation through a symbolic link.' >&2; exit 1; }
done
mkdir -p "$TASK_APP/Contents/MacOS" "$HOME/Library/LaunchAgents"
xcrun swiftc "$SCRIPT_DIR/ScannerStatus.swift" -o "$TASK_APP/Contents/MacOS/DaedalusScannerStatus"
python3 - "$TASK_APP" "$TASK_PLIST" <<'PY'
import sys,plistlib,pathlib,os
app=pathlib.Path(sys.argv[1]);plist=pathlib.Path(sys.argv[2])
(app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'DaedalusScannerStatus','CFBundleIdentifier':'org.daedalus.scanner-status','CFBundleName':'Daedalus Scanner Status','CFBundlePackageType':'APPL','LSUIElement':True,'NSAppTransportSecurity':{'NSAllowsLocalNetworking':True}}))
plist.write_bytes(plistlib.dumps({'Label':'org.daedalus.scanner-status','ProgramArguments':[str(app/'Contents/MacOS/DaedalusScannerStatus'),'--background'],'RunAtLoad':True,'KeepAlive':{'SuccessfulExit':False},'ProcessType':'Interactive'}));plist.chmod(0o600)
PY
codesign --force --sign - "$TASK_APP" >/dev/null 2>&1
launchctl bootout "gui/$(id -u)/$TASK_LABEL" 2>/dev/null || true
TASK_ATTEMPT=0
until launchctl bootstrap "gui/$(id -u)" "$TASK_PLIST" 2>/dev/null; do
 TASK_ATTEMPT=$((TASK_ATTEMPT + 1))
 [ "$TASK_ATTEMPT" -lt 10 ] || { echo "The status login service could not start." >&2; exit 1; }
 sleep 1
done
echo 'Daedalus scanner status installed in the menu bar and enabled at login.'
