# ZK Header Verifier

WASM contract for Magi that verifies SP1 Groth16 proofs of Ethereum consensus and stores ZK-verified block headers. Permissionless proof submission with hash chain verification. Read by the EVM bridge via `contracts.read()` for trustless deposit/withdrawal verification.

## How it works

1. A prover generates an SP1-Helios Groth16 proof that an Ethereum block is finalized
2. The prover submits the proof + RLP-encoded block headers to this contract
3. The contract verifies the proof via the `crypto.sp1_verify_groth16` host function
4. The contract verifies the hash chain: `keccak256(RLP(header))` must match the ZK-proven block hash
5. Verified headers are stored in the same format as the EVM mapping contract's blocklist
6. A proof's batch holds at most 12 headers but finalized checkpoints are ~32 blocks apart, so a batch that does not reach the stored chain opens a gap: its headers are stored and `submitHeaders` backfills the blocks below them, newest first, until the backfill meets the stored chain. No new proof is accepted while a gap is open
7. The EVM bridge reads verified headers via `contracts.read(verifierContractId, key)`

## Actions

| Action | Caller | Description |
|--------|--------|-------------|
| `init` | Owner | One-shot. Set Groth16 VK, VK root, SP1 program vkey hash, anchor (initial block hash + height), `expected_chain_id`, the beacon bootstrap (`genesis_root`, `initial_sync_committee_hash`, `initial_head`), and `is_testnet`. Re-entry rejected. |
| `propose` | Owner | Queue an admin action (`updateVkey` or `setExpectedElfHash` rotation) under the **400K-block timelock** (~14 days). Returns a proposal id. |
| `execute` | Owner | Apply a previously-proposed action after its timelock has elapsed. |
| `cancelProposal` | Owner | Cancel a still-pending proposal before its `execHeight`. |
| `expireProposal` | Anyone | Permissionless garbage-collect of a proposal whose `expireHeight` has passed. |
| `setExpectedElfHash` | Owner | **First pin only** (deploy ramp-up, no trusted prior hash to rotate from). After the first call, this action is rejected — rotations go through `propose` + `execute`. |
| `submitProof` | Anyone | Submit ZK proof + headers. Proof must be valid. Max 12 headers per tx. The proof must continue the stored beacon head from a trusted sync committee on the bound chain (`genesis_root`). A batch above the stored tip + 1 that does not link to it opens a gap; refused while a gap is open. |
| `submitHeaders` | Anyone | Backfill an open gap: up to 12 headers, oldest first, the last one the parent of the lowest stored header. Closes the gap when the batch starts at the stored tip + 1 and links to it; refused (gap stays open) if it does not link. |

`updateVkey` is no longer a direct wasmexport — it is reachable only via `propose` (action `"updateVkey"`) and `execute` after the 400K-block timelock (F1 fix). The init path remains the one place a vkey is installed without timelock (no trusted prior state to rotate from).

## State keys

| Key | Value | Compatible with |
|-----|-------|-----------------|
| `h` | Last verified block height | evm-mapping-contract `GetLastHeight()` |
| `b-{N}` | 137-byte binary block header (v1, chainId label last) | evm-mapping-contract `GetHeader(N)` |
| `lbh` | Hash of the newest stored header (`0x`-prefixed) | — |
| `gapw` / `gapl` | Open gap: hash the next backfilled header must have / lowest backfilled height | — |
| `gapb` / `gapa` | Open gap: stored tip height and hash the backfill must meet | — |
| `vk` | Groth16 VK hex | — |
| `vr` | VK root hex | — |
| `sp1vk` | SP1 program vkey hash hex | — |

## Security

- Proof verification via BN254 pairing check (gnark-crypto on the Go host)
- Hash chain verification: every header's `keccak256(RLP)` verified against proven block hash
- Parent hash chain: each header's parentHash must equal `keccak256(RLP)` of the previous header
- Sequential block numbers enforced
- Max 12 headers per call; the node caps a call's payload at 8192 bytes, which fits ~5 Prague headers next to a proof and ~6 in a backfill
- Backfilled headers hash into a proven block the same way; the gap closes only where the backfill links to the stored chain, and fails closed otherwise
- Old headers pruned automatically (`max_retention`, default 50,400 blocks / 7 days, at least 7,200); backfill keeps the same window
- Storage dominates the cost: ~2,640 RC per stored header (19 RC a written byte), so relaying every block takes ~19M RC a day

## Prerequisites

Requires the `crypto.sp1_verify_groth16` host function in go-vsc-node. See [go-vsc-node feature/zk-eth-oracle branch](https://github.com/vsc-eco/go-vsc-node). All validator nodes must update before this contract is deployed.

## Build

```bash
make            # builds bin/main.wasm via tinygo in Docker; skips if up to date
make clean      # remove bin/*.wasm
make test       # run Go tests on the host toolchain
```

Output: `bin/main.wasm` (~192 KB).

By default the build runs inside the `tinygo/tinygo:0.41.1` Docker image, pinned by immutable digest (`@sha256:b216f534…`) in the Makefile for reproducibility. To use a host tinygo install instead: `USE_DOCKER=0 make`.

## Init parameters

After deployment, call `init` with:

```json
{
  "groth16_vk": "<hex: 492-byte Groth16 verification key for the SP1 version>",
  "vk_root": "<hex: 32-byte SP1 recursion VK root>",
  "sp1_vkey_hash": "<hex: 32-byte SP1 program verification key hash>",
  "max_retention": 50400,
  "initial_height": 12345678,
  "initial_block_hash": "0x<64-hex: finalized L1 block hash at initial_height>",
  "expected_chain_id": 1,
  "genesis_root": "0x<64-hex: the chain's genesis validators root>",
  "initial_sync_committee_hash": "0x<64-hex: hash of the current sync committee at initial_head>",
  "initial_head": 12345664,
  "is_testnet": false
}
```

Generate the whole payload with `magi_genesis` in sp1-helios-magi (see its README). It takes every field from one beacon light-client bootstrap at a finalized checkpoint, checks the anchor against that beacon header, and prints the VK, VK root and program vkey of the SP1 version and ELF the operator proves with. It sends nothing; review the output, then call `init`.

The checkpoint is this verifier's trust root: for a real init, run `magi_genesis` without `--slot` (its checkpoint then comes from checkpoint-sync services, independent of the consensus RPC); with `--slot`, compare the checkpoint root it prints with an independent source first.

Required / important fields (init fails closed if missing):

- `initial_height` + `initial_block_hash` — CRIT #25 anchor. The stored
  chain starts at this block: the first proof's batch either links to it or
  opens a gap that `submitHeaders` backfills down to it. Pick a recent
  finalized L1 block and its hash from a trusted source. Both REQUIRED (init
  aborts if absent/zero).
- `expected_chain_id` — the L1 chainId label (`1` mainnet, `11155111`
  Sepolia) stamped into every stored header, which account-mapping checks
  against its own chainId. REQUIRED, non-zero. It is not compared with the
  proof: chain identity comes from `genesis_root` and the sync committee.
  Immutable after init (no setter).
- `genesis_root`, `initial_sync_committee_hash`, `initial_head` — the beacon
  bootstrap. `genesis_root` pins the chain: every proof must commit it.
  `initial_sync_committee_hash` seeds the trusted committee for
  period(`initial_head`), and the first proof must start from that committee.
  `initial_head` is the bootstrap's checkpoint slot (a multiple of 32);
  `magi_genesis` takes the anchor above from the execution block that
  checkpoint finalizes. All three REQUIRED (init aborts if any is absent or
  zero).
- `max_retention` — optional; defaults to `DefaultMaxRetention` (50,400 blocks,
  about 7 days) when `0`, and must be at least `MinMaxRetention` (7,200).
- `is_testnet` — set `true` ONLY on testnet so `clearTestnetState` is
  permitted; leave `false`/unset on mainnet (the sentinel gates that handler).
