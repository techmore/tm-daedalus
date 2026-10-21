#!/usr/bin/env bash
# Offline shell/file lifecycle only: Python, pip, browser and PDF work are inert stubs.
set -euo pipefail
[[ -f /.dockerenv || -f /run/.containerenv ]] || { echo 'Disposable container required' >&2; exit 2; }
useradd --system --no-create-home --user-group daedalus
mkdir -p /data /fixture-data/payload/daedalus-release/src /opt/daedalus
chmod 0755 /opt /opt/daedalus
printf 'persistent evidence' > /data/keep
printf 'outside sentinel' > /tmp/keep
touch /fixture-data/payload/daedalus-release/requirements-production.txt
tar -czf /fixture-data/release.tar.gz -C /fixture-data/payload daedalus-release
digest=$(sha256sum /fixture-data/release.tar.gz | cut -d' ' -f1)
old=$(printf 'a%.0s' {1..64})
stage=/opt/daedalus/.deploy-11111111111111111111111111111111
candidate=/opt/daedalus/releases/$digest

cat > /usr/local/bin/python3.12 <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == -m && $2 == venv ]]
mkdir -p "$3/bin" "$3/site"
cat > "$3/bin/python" <<'PYTHON'
#!/usr/bin/env bash
set -euo pipefail
base=$(dirname "$(dirname "$0")")
if [[ ${1:-} == -c && $2 == *sysconfig* ]]; then
  printf '%s\n' "$base/site"
elif [[ ${1:-} == -c ]]; then
  if [[ ${FAIL_SMOKE:-0} == 1 ]]; then exit 9; fi
  if [[ ${INTERRUPT_SMOKE:-0} == 1 ]]; then kill -TERM "$PPID"; exit 9; fi
  [[ $DAEDALUS_DATA_DIR == /opt/daedalus/.deploy-*/smoke ]]
  mkdir -p "$DAEDALUS_REPORTS_DIR"
  printf 'inert smoke fixture' > "$DAEDALUS_REPORTS_DIR/fixture"
fi
PYTHON
chmod 0755 "$3/bin/python"
EOF
chmod 0755 /usr/local/bin/python3.12

reset_fixture() {
  rm -rf /opt/daedalus
  mkdir -m 0755 /opt/daedalus
  mkdir -m 0755 /opt/daedalus/releases
  mkdir -m 0755 "/opt/daedalus/releases/$old"
  printf 'prior release' > "/opt/daedalus/releases/$old/keep"
  ln -s "/opt/daedalus/releases/$old" /opt/daedalus/app
  bash /fixture/bootstrap.sh "$stage"
  install -m 0600 /fixture/helper.sh "$stage/deploy-remote.sh"
  install -m 0600 /fixture-data/release.tar.gz "$stage/release.tar.gz"
}
phase() { bash "$stage/deploy-remote.sh" "$1" "$digest" fixture "$stage"; }
refused() {
  if "$@" > /fixture-data/refusal.log 2>&1; then echo 'Unexpected success' >&2; exit 1; fi
}
sentinels() {
  [[ $(cat /data/keep) == 'persistent evidence' && $(cat /tmp/keep) == 'outside sentinel' ]]
  [[ $(cat "/opt/daedalus/releases/$old/keep") == 'prior release' ]]
}

reset_fixture
# shellcheck disable=SC2016 # Expansion must happen in the unprivileged child.
refused runuser -u daedalus -- bash -c 'printf bad > "$1/release.tar.gz"' fixture "$stage"
refused runuser -u daedalus -- mv "$stage/release.tar.gz" /tmp/stolen
[[ $(sha256sum "$stage/release.tar.gz" | cut -d' ' -f1) == "$digest" ]]
phase prepare
[[ -f $candidate/requirements-production.txt && $(readlink /opt/daedalus/app) == "/opt/daedalus/releases/$old" ]]
refused phase prepare # retry never deletes an already prepared candidate
[[ -d $candidate ]]
phase activate
phase activate # safe retry
[[ $(readlink /opt/daedalus/app) == "$candidate" ]]
phase rollback
phase rollback
[[ $(readlink /opt/daedalus/app) == "/opt/daedalus/releases/$old" ]]
phase cleanup
[[ ! -e $stage && -d $candidate ]]
bash /fixture/helper.sh cleanup "$digest" fixture "$stage" # cleanup retry
sentinels
echo 'PASS private archive blocks service-user replacement; prepare/activate/rollback/cleanup retries preserve releases and data'

reset_fixture
chmod 0755 "$stage"
refused phase prepare
[[ ! -e $candidate ]]
chmod 0700 "$stage"
chown daedalus:daedalus "$stage"
refused phase prepare
chown root:root "$stage"
for file in release.tar.gz deploy-remote.sh; do
  chmod 0666 "$stage/$file"
  refused phase prepare
  chmod 0600 "$stage/$file"
  chown daedalus:daedalus "$stage/$file"
  refused phase prepare
  chown root:root "$stage/$file"
done
rm "$stage/release.tar.gz"
ln -s /fixture-data/release.tar.gz "$stage/release.tar.gz"
refused phase prepare
rm "$stage/release.tar.gz"
install -m 0600 /fixture-data/release.tar.gz "$stage/release.tar.gz"
ln "$stage/release.tar.gz" "$stage/second-link"
refused phase prepare
rm "$stage/second-link"
printf tampered >> "$stage/release.tar.gz"
refused phase prepare
[[ ! -e $candidate ]]
sentinels
echo 'PASS unsafe owner/mode, symlink/hardlink archives and digest mismatch refuse preparation'

reset_fixture
mv "$stage" /opt/daedalus/other-stage
ln -s /opt/daedalus/other-stage "$stage"
refused phase cleanup
refused bash /fixture/bootstrap.sh "$stage"
[[ -f /opt/daedalus/other-stage/release.tar.gz ]]
rm "$stage"
mv /opt/daedalus /opt/real-daedalus
ln -s /opt/real-daedalus /opt/daedalus
refused bash /fixture/bootstrap.sh "$stage"
rm /opt/daedalus
mv /opt/real-daedalus /opt/daedalus
chmod 0777 /opt/daedalus
refused bash /fixture/bootstrap.sh "$stage"
chmod 0755 /opt/daedalus
sentinels
echo 'PASS bootstrap refuses symlink/writable ancestors and existing attempts; cleanup refuses a replaced staging symlink'

reset_fixture
export FAIL_SMOKE=1
refused phase prepare
unset FAIL_SMOKE
[[ ! -e $candidate && -f $stage/release.tar.gz ]]
phase prepare # clean retry after failed preparation
phase activate
phase rollback
sentinels
echo 'PASS failed preparation removes only its incomplete candidate and can be retried'

reset_fixture
export INTERRUPT_SMOKE=1
refused phase prepare
unset INTERRUPT_SMOKE
[[ ! -e $candidate && -f $stage/release.tar.gz ]]
sentinels
echo 'PASS interrupted preparation preserves evidence and prior release'

reset_fixture
rm /opt/daedalus/app
mkdir /opt/daedalus/app
printf legacy > /opt/daedalus/app/legacy
phase prepare
phase activate
phase rollback
[[ $(cat /opt/daedalus/app/legacy) == legacy ]]
phase cleanup
sentinels
echo 'PASS legacy real application tree survives activation and rollback'
