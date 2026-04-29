# ZK Header Verifier

WASM contract for Magi that verifies SP1 Groth16 proofs of Ethereum consensus and stores ZK-verified block headers. Permissionless proof submission with hash chain verification. Read by the EVM bridge via `contracts.read()` for trustless deposit/withdrawal verification.

## How it works

1. A prover generates an SP1-Helios Groth16 proof that an Ethereum block is finalized
2. The prover submits the proof + RLP-encoded block headers to this contract
3. The contract verifies the proof via the `crypto.sp1_verify_groth16` host function
4. The contract verifies the hash chain: `keccak256(RLP(header))` must match the ZK-proven block hash
5. Verified headers are stored in the same format as the EVM mapping contract's blocklist
6. The EVM bridge reads verified headers via `contracts.read(verifierContractId, key)`

## Actions

| Action | Caller | Description |
|--------|--------|-------------|
| `init` | Owner | Set Groth16 VK, VK root, and SP1 program vkey hash |
| `updateVkey` | Owner | Update verification parameters (for SP1 version upgrades) |
| `submitProof` | Anyone | Submit ZK proof + headers. Proof must be valid. Max 12 headers per tx. |

## State keys

| Key | Value | Compatible with |
|-----|-------|-----------------|
| `h` | Last verified block height | evm-mapping-contract `GetLastHeight()` |
| `b-{N}` | 128-byte binary block header | evm-mapping-contract `GetHeader(N)` |
| `vk` | Groth16 VK hex | — |
| `vr` | VK root hex | — |
| `sp1vk` | SP1 program vkey hash hex | — |

## Security

- Proof verification via BN254 pairing check (gnark-crypto on the Go host)
- Hash chain verification: every header's `keccak256(RLP)` verified against proven block hash
- Parent hash chain: each header's parentHash must equal `keccak256(RLP)` of the previous header
- Sequential block numbers enforced
- Max 12 headers per transaction (16KB tx size limit)
- Old headers pruned automatically (10,000 block retention)

## Prerequisites

Requires the `crypto.sp1_verify_groth16` host function in go-vsc-node. See [go-vsc-node feature/zk-eth-oracle branch](https://github.com/vsc-eco/go-vsc-node). All validator nodes must update before this contract is deployed.

## Build

```bash
tinygo build -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown -o contract.wasm ./contract/
```

Compiled WASM: 179 KB (included as `contract.wasm`)

## Init parameters

After deployment, call `init` with:

```json
{
  "groth16_vk": "<hex: 492-byte Groth16 verification key for the SP1 version>",
  "vk_root": "<hex: 32-byte SP1 recursion VK root>",
  "sp1_vkey_hash": "<hex: 32-byte SP1 program verification key hash>"
}
```

These values come from the SP1-Helios fork's build output and the SP1 verifier artifacts.
