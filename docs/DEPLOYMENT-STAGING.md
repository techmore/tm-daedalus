# Protected deployment staging

Deployment gate: [#13](https://github.com/techmore/tm-daedalus/issues/13).

Each attempt creates a fresh random directory on the SSH host (`/tmp/daedalus-deploy-<attempt>`, mode 0700, owned by the SSH operator) and inside Incus (`/opt/daedalus/.deploy-<attempt>`, root:root, mode 0700). Existing attempt directories are never reused automatically. The container parent directories must be real root-owned directories without group/other write access. Bootstrap validates them before copying any executable helper.

Incus pushes the archive and helper as root:root, mode 0600. The helper refuses unsafe ownership/modes, symbolic links and multiply linked archive files. It opens the archive once; checksum verification and extraction use that same descriptor inside the protected directory. The service user cannot traverse the directory or replace staged bytes between verification and extraction.

Preparation stores its smoke-test data and rollback pointer inside the attempt directory. It never writes `/data`. The existing stable application path, persistent volume, release archive verification, dependency hashes, synthetic PDF smoke check, health checks and prior release retention remain in the normal deployment procedure.

## Failures, interruption and cleanup

A failed or signalled preparation removes only its incomplete candidate. It does not delete the existing application or prior releases. A repeated prepare refuses an existing candidate; repeated activation or rollback is safe for the same attempt. Cleanup removes only the validated private attempt directory and supports a repeated call after removal.

The coordinator cleans up after verified healthy activation or verified healthy rollback. A failed/uncertain prepare, interrupted remote phase, or unverified rollback retains both host and container staging. Output identifies the recovery paths. Do not delete these directories while a remote operation may still run. Establish the active source and service health first; then use the retained root helper and its `previous` pointer for operator-reviewed recovery. The helper's fourth argument is the exact private container directory:

```sh
bash /opt/daedalus/.deploy-<attempt>/deploy-remote.sh rollback <archive-sha256> daedalus-prod /opt/daedalus/.deploy-<attempt>
```

The attempt is a 32-character lowercase hexadecimal value, not a literal placeholder. The existing Incus restart and internal/public health verification still follow a rollback; invoking the helper alone does not prove recovery. Failed optional cleanup retains its existing bounded SSH/access-check behavior. The attempt files contain no application secrets by design, but remain private.

Concurrent deployment coordination and live recovery acceptance remain operational concerns; private per-attempt staging prevents file clobbering and is not a deployment lock. No production rollout is implied by merging this change.

## Validation

`python3 scripts/validate_deploy_staging.py --runtime docker` runs the actual root helper in a disposable container with network disabled and only fixture inputs mounted read-only. Podman is also supported. This tests archive replacement attempts by the service user, unsafe ownership/modes, symlink/hardlink refusal, digest mismatch, failed/interrupted preparation, existing/repeated attempts, activation/rollback/cleanup and legacy application recovery. Sentinels check that persistent data and prior releases survive. Dependency installation, browser installation and the PDF renderer are inert stubs in this security/lifecycle fixture; the existing application suite exercises report behavior separately.

The `Protected deployment staging` CI job runs this fixture in Ubuntu 24.04. Local validation on October 20, 2026 used the existing Ubuntu resolute image (`b16e02b102dc`), with all six scenario groups passing. Coordinator unit tests also cover interrupted uploads, uncertain remote results and retained rollback state. No real SSH/Incus host, production service, network scan or merchant data was accessed for this change.
