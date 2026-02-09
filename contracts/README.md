## Contracts (Base)

Base-side contracts for the Juno <-> Base bridge.

### Suite

- `Bridge.sol`: verifies operator-quorum checkpoints + zk proofs, mints on deposit, escrows/burns on withdraw
- `WJuno.sol`: `wJUNO` ERC-20 with `permit`; mint/burn restricted to `Bridge`
- `FeeDistributor.sol`: O(1) fee accounting + operator claims (no loops on mint/finalize)
- `OperatorRegistry.sol`: operator membership + threshold config + fee recipient/weight updates

## Documentation

Testing and tooling uses Foundry: https://book.getfoundry.sh/

## Usage

### Build

```shell
forge build
```

### Test

```shell
forge test
```

### Format

```shell
forge fmt
```

### Gas Snapshots

```shell
forge snapshot
```

### Anvil

```shell
anvil
```

### Cast

```shell
cast <subcommand>
```

### Help

```shell
forge --help
anvil --help
cast --help
```
