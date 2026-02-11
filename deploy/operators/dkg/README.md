# Online DKG Scripts (Linux + macOS)

This folder contains reusable scripts for online `dkg-ceremony` / `dkg-admin` operations.

## Scripts

- `tailscale.sh`: operator-side Tailscale bootstrap + registration payload output.
- `operator.sh`: operator-side bundle execution (`dkg-admin serve`) and process control.
- `coordinator.sh`: coordinator-side ceremony initialization, preflight, online run/resume, and export.
- `common.sh`: shared helpers (dependency install, binary install, validation, Tailscale checks).

## Operator Flow

1. Generate registration payload:

```bash
./deploy/operators/dkg/tailscale.sh register \
  --port 8443 \
  --fee-recipient 0x... \
  --output ./operator-registration.json \
  --network mainnet
```

2. Send `operator-registration.json` to coordinator.
3. Receive your bundle tarball from coordinator.
4. Start `dkg-admin`:

```bash
./deploy/operators/dkg/operator.sh run \
  --bundle ./1_0x....tar.gz \
  --workdir ~/.juno-dkg/operator-runtime \
  --daemon
```

## Coordinator Flow

1. Initialize ceremony workspace from operator registrations:

```bash
./deploy/operators/dkg/coordinator.sh init \
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

2. Distribute bundle tarballs from `./dkg-mainnet-2026-02-11/bundles/`.
3. Run preflight:

```bash
./deploy/operators/dkg/coordinator.sh preflight --workdir ./dkg-mainnet-2026-02-11
```

4. Run online ceremony:

```bash
./deploy/operators/dkg/coordinator.sh run --workdir ./dkg-mainnet-2026-02-11
```

5. If interrupted:

```bash
./deploy/operators/dkg/coordinator.sh resume --workdir ./dkg-mainnet-2026-02-11
```

6. Export key packages with primary KMS+S3 plus local age backup:

```bash
./deploy/operators/dkg/coordinator.sh export \
  --workdir ./dkg-mainnet-2026-02-11 \
  --kms-key-id arn:aws:kms:... \
  --s3-bucket my-bucket \
  --s3-key-prefix dkg/keypackages \
  --s3-sse-kms-key-id arn:aws:kms:... \
  --backup-age-recipient age1...
```

## Notes

- `preflight`, `run`, `resume`, and `export` require active Tailscale connectivity.
- Endpoints are per-operator and can share hostname with different ports.
- Bundles include `operator-metadata.json` with `fee_recipient` for later operator deployment wiring.
- Tools default to release `v0.1.0` and auto-download by OS/arch. You can override with:
  - `JUNO_DKG_ADMIN_BIN=/path/to/dkg-admin`
  - `JUNO_DKG_CEREMONY_BIN=/path/to/dkg-ceremony`

