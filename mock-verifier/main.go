// DEVNET TEST DOUBLE — mock ZK header verifier. NOT a production contract.
//
// Purpose: let the account-mapping bridge be devnet-tested WITHOUT a real SP1
// proof. account-mapping
// reads block headers from its configured verifier purely via a cross-contract
// state read of the verifier's `b-{height}` key (blocklist/blocks.go readState
// -> sdk.ContractStateGet). This mock exposes the SAME read surface: it writes
// `b-{height}` in the EXACT 137-byte layout the real zk-review6 verifier's
// storeHeader produces (so account-mapping's DeserializeHeader reads it
// identically) — but via a permissionless devnet `devSetHeader` that plants a
// header with REAL, independently-verified roots, BYPASSING the groth16 verify.
//
// ONLY the ZK-authenticity write-gate is mocked. Everything account-mapping does
// downstream (tx-trie / receipt-trie MPT verification against the planted REAL
// receiptsRoot/transactionsRoot, ABI, the withdrawal state machine, ecrecover)
// runs for real against real roots.
//
// storeHeader + appendUint64 below are COPIED BYTE-IDENTICAL from
// zk-header-verifier/contract/main.go (storeHeader@700, the W4 Cluster B Site
// 4/6 unified 137-byte layout). If that layout ever changes, update here too.
package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	ce "zk-header-verifier/contract/contracterrors"
	"zk-header-verifier/sdk"
)

func main() {}

// --- keys + layout: must match zk-review6 contract/main.go exactly ---
const (
	KeyLastHeight    = "h"
	KeyBlockPrefix   = "b-"
	KeyLastBlockHash = "lbh"
)

const HeaderVersionV1 byte = 0x01
const HeaderSerializedSize = 137

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// storeHeader — byte-identical to zk-header-verifier/contract/main.go:700.
func storeHeader(blockNumber uint64, stateRoot, txRoot, rcptRoot [32]byte, baseFee, gasLimit, timestamp, chainId uint64) {
	buf := make([]byte, 0, HeaderSerializedSize)
	buf = append(buf, HeaderVersionV1)
	buf = appendUint64(buf, blockNumber)
	buf = append(buf, stateRoot[:]...)
	buf = append(buf, txRoot[:]...)
	buf = append(buf, rcptRoot[:]...)
	buf = appendUint64(buf, baseFee)
	buf = appendUint64(buf, gasLimit)
	buf = appendUint64(buf, timestamp)
	buf = appendUint64(buf, chainId)
	sdk.StateSetObject(KeyBlockPrefix+strconv.FormatUint(blockNumber, 10), string(buf))
}

//go:wasmexport init
func initContract(input *string) *string {
	// Mark testnet sentinel; the mock is inert as a production verifier
	// (it has no submitProof / groth16 path at all). Idempotent. Anyone can
	// call init, so the sentinel does not stop devSetHeader on a deployed mock:
	// only never deploying the mock to mainnet (and the bridge's timelocked
	// setVerifierContract) does.
	sdk.StateSetObject("is_testnet", "true")
	return nil
}

type devSetHeaderParams struct {
	BlockNumber  uint64 `json:"block_number"`
	StateRoot    string `json:"state_root"`
	TxRoot       string `json:"tx_root"`
	ReceiptsRoot string `json:"receipts_root"`
	BaseFee      uint64 `json:"base_fee"`
	GasLimit     uint64 `json:"gas_limit"`
	Timestamp    uint64 `json:"timestamp"`
	ChainId      uint64 `json:"chain_id"`
	BlockHash    string `json:"block_hash"` // optional; sets lbh for parity
}

// hexRoot parses a 32-byte root (optional 0x prefix) or aborts.
func hexRoot(s, field string) [32]byte {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		ce.Abort(ce.ErrInput, "expected 32-byte hex for "+field, "devSetHeader")
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

//go:wasmexport devSetHeader
func devSetHeader(input *string) *string {
	// DEVNET ONLY: plant a header with real roots, no proof. Guarded by the
	// testnet sentinel so an accidental mainnet deploy cannot inject headers.
	if t := sdk.StateGetObject("is_testnet"); t == nil || *t != "true" {
		ce.Abort(ce.ErrState, "devSetHeader is devnet-only (is_testnet sentinel unset)", "devSetHeader")
	}
	var p devSetHeaderParams
	if err := json.Unmarshal([]byte(*input), &p); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON: "+err.Error(), "devSetHeader")
	}
	if p.BlockNumber == 0 || p.ChainId == 0 {
		ce.Abort(ce.ErrInput, "block_number and chain_id required (non-zero)", "devSetHeader")
	}
	stateRoot := hexRoot(p.StateRoot, "state_root")
	txRoot := hexRoot(p.TxRoot, "tx_root")
	rcptRoot := hexRoot(p.ReceiptsRoot, "receipts_root")

	storeHeader(p.BlockNumber, stateRoot, txRoot, rcptRoot, p.BaseFee, p.GasLimit, p.Timestamp, p.ChainId)

	// Track the tip the way the real verifier does, so GetLastHeight-style
	// reads on the mock are coherent across multiple planted headers.
	if cur := sdk.StateGetObject(KeyLastHeight); cur == nil || *cur == "" {
		sdk.StateSetObject(KeyLastHeight, strconv.FormatUint(p.BlockNumber, 10))
	} else if h, err := strconv.ParseUint(*cur, 10, 64); err != nil || p.BlockNumber > h {
		sdk.StateSetObject(KeyLastHeight, strconv.FormatUint(p.BlockNumber, 10))
	}
	if p.BlockHash != "" {
		sdk.StateSetObject(KeyLastBlockHash, p.BlockHash)
	}
	return nil
}
