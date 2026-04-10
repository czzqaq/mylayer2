# Layer1 Execution Engine (Interview Project)

This repository is a **learning-oriented Ethereum execution project in Rust**.
It focuses on the core state transition path of "apply transactions to world state"
rather than full node networking or consensus.

The project is intentionally scoped for technical depth and interview discussion,
not for production deployment.

## Why I built this

I built this project to demonstrate:

- a thorough and precise understanding of the Ethereum Yellow Paper
- proficiency in Rust programming
- ability to understand both theoretical papers and engineering tradeoffs

## What this project currently includes

- **Typed + legacy transaction handling**
  - Supports legacy, EIP-2930 (type 1), and EIP-1559 (type 2) transaction formats.
- **Block import pipeline**
  - Header validity checks against parent.
  - Transaction execution with per-tx receipt generation.
  - Cumulative gas tracking and block-level gas accounting.
- **World state engine**
  - Trie-backed world state and per-account storage.
  - Checkpoint / rollback / commit journal.
- **EVM execution framework**
  - Opcode dispatch through a jump table.
  - Gas charging (intrinsic + runtime), value transfer, CREATE path, refunds.
  - Substate tracking for logs, touched accounts, and self-destruct handling.
- **Spec-inspired protocol features**
  - EIP-155 (legacy replay protection and chain ID semantics).
  - EIP-2718 typed transaction envelope handling.
  - EIP-2930 access list transaction/accounting logic.
  - EIP-1559 dynamic fee mechanics (effective gas price and priority fee).
  - EIP-2028 intrinsic gas accounting for calldata zero/non-zero bytes.
  - EIP-2200/2929-inspired storage gas and warm/cold access handling.
  - EIP-3529 refund-cap logic.
  - EIP-3607 sender-is-EOA transaction validation.
  - EIP-158/EIP-161-inspired empty account lifecycle and state cleanup behavior.
  - EIP-4788 beacon roots system-contract write path.
- **Fixture-driven tests**
  - Uses Ethereum test fixtures to validate tx/block behavior and pre->post state transitions.

## Repository structure

- `src/blockchain.rs`: block import and chain-state transition flow
- `src/tx_execution.rs`: transaction validation + EVM run orchestration
- `src/world_state.rs`: trie-backed world state with journaled checkpoints
- `src/transaction.rs`: tx encoding/decoding, sender recovery, fee helpers
- `src/operations.rs`: opcode table and operation handlers
- `tests/`: integration tests against JSON fixtures

## How to run

### Requirements

- Rust stable toolchain
- Cargo

### Build

```bash
cargo build
```

### Run tests

```bash
cargo test
```

Some tests use fixture files under `tests/data` and `test_data`.

## Known limitations (intentional for scope)

- Not a full Ethereum client (no p2p, no consensus engine, no mempool)
- Not optimized for performance or persistent database storage
- Partial opcode/feature coverage
- Some holistic validation paths are still being tightened against fixtures

## Roadmap

- Expand opcode and precompile coverage
- Improve state root/receipt root parity with broader official fixtures
- Add more robust gas edge-case tests

## References

- [Ethereum Tests](https://github.com/ethereum/tests)
- [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf)
