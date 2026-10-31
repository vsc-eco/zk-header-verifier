# ZK Header Verifier

WASM contract for Magi that verifies SP1 Groth16 proofs of Ethereum consensus and stores ZK-verified block headers. Permissionless proof submission with hash chain verification. Read by the EVM bridge via `contracts.read()` for trustless deposit/withdrawal verification.

## How it works

1. A prover generates an SP1-Helios Groth16 proof that an Ethereum block is finalized
2. The prover submits the proof + RLP-encoded block headers to this contract
3. The contract verifies the proof via the `crypto.sp1_verify_groth16` host function
4. The contract verifies the hash chain: `keccak256(RLP(header))` must match the ZK-proven block hash
5. Verified headers are stored in the same format as the EVM mapping contract's blocklist
6. A proof stores only its own batch (the proven block, and any headers below it that hash into it); nothing has to be backfilled (RP-9). The header of any other block the bridge uses is stored on demand:
   - `attestHistoryRoot` + `attestHeaders`: an EIP-2935 proof. The history contract `0x0000F90827F1C53a10cb7A02335B175320002935` holds the hashes of the 8,191 blocks before each block in its storage, so a stored block R's state root proves the header of any block R-8191 .. R-1 (account proof once per R, then a storage proof per header)
   - `submitHeaders`: headers linked by parent hash down from a stored header, for blocks no stored root's window covers
7. A stored header is kept `max_retention` blocks (of the proven tip) from when it was stored, then pruned; it can be stored again the same way (RP-6)
8. The EVM bridge reads verified headers via `contracts.read(verifierContractId, key)`

## Actions

| Action | Caller | Description |
|--------|--------|-------------|
| `init` | Owner | One-shot. Set Groth16 VK, VK root, SP1 program vkey hash, anchor (initial block hash + height), `expected_chain_id`, the beacon bootstrap (`genesis_root`, `initial_sync_committee_hash`, `initial_head`), and `is_testnet`. Re-entry rejected. |
| `propose` | Owner | Queue an admin action (`updateVkey` or `setExpectedElfHash` rotation) under the **400K-block timelock** (~14 days). Returns a proposal id. |
| `execute` | Owner | Apply a previously-proposed action after its timelock has elapsed. |
| `cancelProposal` | Owner | Cancel a still-pending proposal before its `execHeight`. |
| `expireProposal` | Anyone | Permissionless garbage-collect of a proposal whose `expireHeight` has passed. |
| `setExpectedElfHash` | Owner | **First pin only** (deploy ramp-up, no trusted prior hash to rotate from). After the first call, this action is rejected — rotations go through `propose` + `execute`. |
| `submitProof` | Anyone | Submit ZK proof + headers (the proven block last; any headers before it must chain into it). Proof must be valid. Max 12 headers per tx. The proof must continue the stored beacon head from a trusted sync committee on the bound chain (`genesis_root`), and the proven block must be above the stored tip `h`, which it becomes. |
| `attestHistoryRoot` | Anyone | `{block_number: R, account_proof}`: the EIP-2935 history contract's account proof (base64, concatenated MPT nodes) against stored block R's state root; its code hash must be the history contract's. Stores the contract's storage root as `hr-{R}`. |
| `attestHeaders` | Anyone | `{root_block: R, headers: [{rlp_hex, storage_proof}]}`: for each header X with R-8191 <= X < R, the storage proof (base64) of slot X % 8191 against `hr-{R}` must hold keccak256(header). Stores each header. Never moves `h`. |
| `submitHeaders` | Anyone | Up to 12 headers, oldest first, chained by parent hash; the last one must hash to the stored parent hash `ph-{last+1}` of the header above it. Stores them. Never moves `h`. |

`updateVkey` is no longer a direct wasmexport — it is reachable only via `propose` (action `"updateVkey"`) and `execute` after the 400K-block timelock (F1 fix). The init path remains the one place a vkey is installed without timelock (no trusted prior state to rotate from).

## State keys

| Key | Value | Compatible with |
|-----|-------|-----------------|
| `h` | The newest proven block (the stored tip) | evm-mapping-contract `GetLastHeight()` |
| `b-{N}` | 137-byte binary block header (v1, chainId label last) | evm-mapping-contract `GetHeader(N)` |
| `ph-{N}` | Parent hash of stored header N (32 raw bytes) | — |
| `hr-{N}` | EIP-2935 history contract storage root in the state of stored block N (32 raw bytes) | — |
| `sl-{seq}` / `slh` / `slt` | Store log for pruning: `{height}:{tip when stored}`, oldest live seq, next seq | — |
| `lbh` | Hash of the newest proven block (`0x`-prefixed), informational | — |
| `vk` | Groth16 VK hex | — |
| `vr` | VK root hex | — |
| `sp1vk` | SP1 program vkey hash hex | — |

## Security

- Proof verification via BN254 pairing check (gnark-crypto on the Go host)
- Hash chain verification: every header's `keccak256(RLP)` verified against proven block hash
- Parent hash chain: each header's parentHash must equal `keccak256(RLP)` of the previous header
- Sequential block numbers enforced
- Max 12 headers per call; the node caps a call's payload at 8192 bytes, which fits ~5 Prague headers next to a proof, ~6 in `submitHeaders`, 2 in `attestHeaders`
- Every stored header is bound to a proven block: by the keccak chain into it, by an EIP-2935 storage proof against a stored state root (MPT verification as go-ethereum's `trie.VerifyProof`), or by parent hash down from a stored header
- EIP-2935 proofs must be fetched while the RPC still serves the state of R (geth keeps 128 blocks; a proven R is already ~64 behind the head): fetch at each newly finalized block. Without such an RPC, `submitHeaders` needs no state
- Headers pruned `max_retention` blocks after they were stored (default 648,000 blocks / 90 days, at least 7,200), at most 2 per store
- Storage dominates the cost (19 RC a written byte). Measured on the node's wasm runtime (real mainnet/Sepolia proofs): `attestHistoryRoot` ~810 RC, `attestHeaders` ~3,720 RC a header, `submitHeaders` ~3,420 RC a header. Only blocks the bridge uses are stored (was every block, ~19M RC a day)

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
