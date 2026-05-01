package main

import (
	"encoding/hex"
	"testing"

	ce "zk-header-verifier/contract/contracterrors"
)

// Real SP1-Helios v6.1.0 ABI-encoded ProofOutputs for Sepolia block 10764834.
// Sourced from go-vsc-node modules/wasm/sdk/sp1_verifier_test.go.
const v6_1_0_PublicValuesHex = "00000000000000000000000000000000000000000000000000000000000000201024268bf088fa5770d276017f20a3fa4e0cc13c5f854b3a8b1f791cc1b85c3a00000000000000000000000000000000000000000000000000000000009af1e04577257aad51ec8b4519e0ba0546f2a032b2534f87f811a19b27b4d42278787d00000000000000000000000000000000000000000000000000000000009af220999525d0726b588e6cc9bd6841eb5393bc0b5137d980b30f8ed136efdd8a348e6efab94327bc2fd7eae04922c44be6be72f4e9f402410df10131be20870dc15e7cfbfa1dcd1490246a97443bbcce8e841e432d25df8f2ad1b6258e06441a3bdf0000000000000000000000000000000000000000000000000000000000a442224577257aad51ec8b4519e0ba0546f2a032b2534f87f811a19b27b4d42278787d4293e591071f6fb96e4a99a578693578bf4a9125c17b20abb845d3861c248ee000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000000"

const (
	expectedStateRoot   = "6efab94327bc2fd7eae04922c44be6be72f4e9f402410df10131be20870dc15e"
	expectedBlockHash   = "7cfbfa1dcd1490246a97443bbcce8e841e432d25df8f2ad1b6258e06441a3bdf"
	expectedBlockNumber = uint64(10764834) // 0xa44222
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func TestParseProvenFields_HappyPath(t *testing.T) {
	pv := mustDecodeHex(t, v6_1_0_PublicValuesHex)

	stateRoot, blockHash, blockNumber, err := parseProvenFields(pv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stateRoot != expectedStateRoot {
		t.Errorf("stateRoot = %q, want %q", stateRoot, expectedStateRoot)
	}
	if blockHash != expectedBlockHash {
		t.Errorf("blockHash = %q, want %q", blockHash, expectedBlockHash)
	}
	if blockNumber != expectedBlockNumber {
		t.Errorf("blockNumber = %d, want %d", blockNumber, expectedBlockNumber)
	}
}

func TestParseProvenFields_TooShort(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one byte short of minimum", PvMinLen - 1},
		{"only the offset prefix", 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parseProvenFields(make([]byte, tt.size))
			if err == nil {
				t.Fatal("expected error for short input, got none")
			}
			if err.Symbol != ce.ErrInput {
				t.Errorf("symbol = %q, want ErrInput", err.Symbol)
			}
		})
	}
}

func TestParseProvenFields_WrongAbiOffset(t *testing.T) {
	pv := mustDecodeHex(t, v6_1_0_PublicValuesHex)

	// Rewrite the offset (bytes [24:32]) from 0x20 to 0x40. Length stays the same,
	// so the length check passes; only the offset check should reject this.
	pv[31] = 0x40

	_, _, _, err := parseProvenFields(pv)
	if err == nil {
		t.Fatal("expected error for non-32 ABI offset, got none")
	}
	if err.Symbol != ce.ErrInput {
		t.Errorf("symbol = %q, want ErrInput", err.Symbol)
	}
}

func TestParseProvenFields_OffsetExactlyAtBoundary(t *testing.T) {
	// Public_values exactly PvMinLen bytes long with valid offset.
	// Should succeed (boundary inclusion check).
	pv := make([]byte, PvMinLen)
	pv[31] = byte(PvAbiOffset) // offset = 32

	// Plant a recognizable block number at the right offset
	pv[PvFieldBlockNumber+31] = 0x42

	_, _, blockNumber, err := parseProvenFields(pv)
	if err != nil {
		t.Fatalf("unexpected error at PvMinLen boundary: %v", err)
	}
	if blockNumber != 0x42 {
		t.Errorf("blockNumber = %d, want 0x42", blockNumber)
	}
}
