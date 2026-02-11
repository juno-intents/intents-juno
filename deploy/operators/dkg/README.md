# Online DKG Scripts (Linux + macOS)

This folder contains reusable scripts for online `dkg-ceremony` / `dkg-admin` operations.

## Scripts

- `tailscale.sh`: operator-side Tailscale bootstrap + registration payload output.
- `operator.sh`: operator-side bundle execution (`dkg-admin serve`) and process control.
- `operator-export-kms.sh`: operator-side key package export workflows (age backup first, KMS+S3 later).
- `coordinator.sh`: coordinator-side ceremony initialization, preflight, and online run/resume.
- `test-completiton.sh`: completion verifier that checks smoke-signature phases and outputs UFVK + Juno shielded address.
- `common.sh`: shared helpers (dependency install, binary install, validation, Tailscale checks).

## Primary Ceremony Flow

### 1) Each operator registers

```bash
./tailscale.sh register \
  --port 8443 \
  --fee-recipient 0x... \
  --output ./operator-registration.json \
  --network mainnet
```

Each operator sends `operator-registration.json` to the coordinator.

### 2) Coordinator initializes workspace

```bash
./coordinator.sh init \
  --workdir ./dkg-mainnet-2026-02-11 \
  --network mainnet \
  --threshold 3 \
  --max-signers 5 \
  --registration-file ./op1.json \
  --registration-file ./op2.json \
  --registration-file ./op3.json \
  --registration-file ./op4.json \
  --registration-file ./op5.json \
  --prompt-endpoints
```

### 3) Coordinator distributes bundles

Send tarballs from `./dkg-mainnet-2026-02-11/bundles/` to matching operators.

### 4) Each operator starts `dkg-admin`

```bash
./operator.sh run \
  --bundle ./1_0x....tar.gz \
  --workdir ~/.juno-dkg/operator-runtime \
  --daemon
```

### 5) Coordinator runs preflight and ceremony

```bash
./coordinator.sh preflight --workdir ./dkg-mainnet-2026-02-11
./coordinator.sh run --workdir ./dkg-mainnet-2026-02-11
```

If interrupted:

```bash
./coordinator.sh resume --workdir ./dkg-mainnet-2026-02-11
```

### 6) Verify completion and extract UFVK/shielded address

```bash
./test-completiton.sh run \
  --workdir ./dkg-mainnet-2026-02-11 \
  --output ./dkg-mainnet-2026-02-11/reports/test-completiton.json
```

This command validates online smoke-signature phases for all operators and prints JSON with:

- `ufvk`
- `juno_shielded_address` (from `owallet_ua`)
- `public_key_package_hash`
- `transcript_hash`

## Primary Post-DKG Export Flow (Age First, KMS Later)

### 1) Generate age recipient on each operator

```bash
./operator-export-kms.sh age-recipient \
  --output ~/.juno-dkg/backup/age-recipient.json
```

### 2) Export age backup only (no AWS required yet)

```bash
./operator-export-kms.sh backup-age \
  --workdir ~/.juno-dkg/operator-runtime \
  --age-recipient age1... \
  --out ~/.juno-dkg/exports/keypackage-backup.json
```

### 3) Later, export to each operator's own KMS+S3 target

Option A (if runtime state is still present): run `export` directly from runtime:

```bash
./operator-export-kms.sh export \
  --workdir ~/.juno-dkg/operator-runtime \
  --kms-key-id arn:aws:kms:... \
  --s3-bucket my-operator-bucket \
  --s3-key-prefix dkg/keypackages \
  --s3-sse-kms-key-id arn:aws:kms:... \
  --aws-profile juno-prod \
  --aws-region us-east-1
```

Option B (if using backup artifacts, without runtime state): rewrap from age backup:

```bash
./operator-export-kms.sh rewrap-age-to-kms \
  --age-backup-file ~/.juno-dkg/exports/keypackage-backup.json \
  --age-identity-file ~/.juno-dkg/backup/age-identity.txt \
  --admin-config ~/.juno-dkg/backup/admin-config.json \
  --kms-key-id arn:aws:kms:... \
  --s3-bucket my-operator-bucket \
  --s3-key-prefix dkg/keypackages \
  --s3-sse-kms-key-id arn:aws:kms:... \
  --aws-profile juno-prod \
  --aws-region us-east-1
```

`rewrap-age-to-kms` requires both:

- the age backup blob, and
- the operator `admin-config.json` backup.

Age backup alone is not sufficient because re-export validation needs ceremony/roster config metadata.

## Where `age-recipient` Comes From

Generate or reuse an age identity key on the operator machine:

```bash
./operator-export-kms.sh age-recipient
```

This prints JSON with:

- `age_recipient`: the public recipient (`age1...`) to pass in `backup-age --age-recipient`.
- `identity_file`: the local private key path to back up securely.

## Backup Checklist (Store Externally)

Each operator should back up these artifacts outside the machine:

1. Age private identity file:
   - `~/.juno-dkg/backup/age-identity.txt`
2. Age backup blob:
   - `~/.juno-dkg/exports/keypackage-backup.json`
3. Age backup receipt:
   - `~/.juno-dkg/exports/keypackage-backup.json.KeyImportReceipt.json`
4. Operator admin config backup (needed for rewrap):
   - copy from bundle: `admin-config.json`
5. Completion report for audit trail:
   - `<workdir>/reports/test-completiton.json`

## Optional Coordinator-Wide Export

`coordinator.sh export` still exists for cases where all operators intentionally share one export target configuration.

## Notes

- `preflight`, `run`, and `resume` require active Tailscale connectivity.
- Endpoints are per-operator and can share hostname with different ports.
- Bundles include `operator-metadata.json` with `fee_recipient` for later operator deployment wiring.
- Scripts auto-attempt execution remediation on startup:
  - macOS: recursively removes `com.apple.quarantine` in the DKG script folder.
  - Linux/macOS: repairs executable permission bits on downloaded/packaged binaries.
- Tools default to release `v0.1.0` and auto-download by OS/arch. You can override with:
  - `JUNO_DKG_ADMIN_BIN=/path/to/dkg-admin`
  - `JUNO_DKG_CEREMONY_BIN=/path/to/dkg-ceremony`
