# intents-juno

Monorepo scaffold for the Juno <-> Base bridge implementation.

## Layout

- `cmd/`: Go binaries (relayers, coordinators, API, ceremony/admin tools)
- `internal/`: shared Go packages (config, batching, memo formats, idempotency, queue/blobstore adapters)
- `contracts/`: EVM contracts
- `zk/`: zkVM guest programs
- `deploy/`:
  - `deploy/shared/`: shared services (optional)
  - `deploy/operators/`: per-operator deployment
