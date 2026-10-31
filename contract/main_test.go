package main

import (
	"encoding/hex"
	"testing"

	ce "zk-header-verifier/contract/contracterrors"
)

// Real SP1-Helios v6.1.0 ABI-encoded ProofOutputs for Sepolia block 10764834.
// Sourced from go-vsc-node modules/wasm/sdk/sp1_verifier_test.go.
//
// NOTE: this is the PRE-genesisRoot fixture (11-field struct ending in an empty
// storageSlots[] array; 13 ABI words / 416 bytes). Under the current parser,
// tuple slots 0–9 still decode correctly (they are unchanged between the old and
// new struct) — so the execution fields AND the beacon committee/head fields
// below are real and asserted. Only `genesisRoot` (slot 10) is stale here: the
// old corpus has the storageSlots offset-pointer word (0x160) at byte 352, so
// the parser reads genesisRoot == 0x…0160, which is NOT a real GVR. Once the
// rebuilt prover emits genesisRoot, regenerate this fixture (plan C2) and add a
// real genesisRoot assertion to the golden test.
const v6_1_0_PublicValuesHex = "00000000000000000000000000000000000000000000000000000000000000201024268bf088fa5770d276017f20a3fa4e0cc13c5f854b3a8b1f791cc1b85c3a00000000000000000000000000000000000000000000000000000000009af1e04577257aad51ec8b4519e0ba0546f2a032b2534f87f811a19b27b4d42278787d00000000000000000000000000000000000000000000000000000000009af220999525d0726b588e6cc9bd6841eb5393bc0b5137d980b30f8ed136efdd8a348e6efab94327bc2fd7eae04922c44be6be72f4e9f402410df10131be20870dc15e7cfbfa1dcd1490246a97443bbcce8e841e432d25df8f2ad1b6258e06441a3bdf0000000000000000000000000000000000000000000000000000000000a442224577257aad51ec8b4519e0ba0546f2a032b2534f87f811a19b27b4d42278787d4293e591071f6fb96e4a99a578693578bf4a9125c17b20abb845d3861c248ee000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000000"

const (
	expectedStateRoot   = "6efab94327bc2fd7eae04922c44be6be72f4e9f402410df10131be20870dc15e"
	expectedBlockHash   = "7cfbfa1dcd1490246a97443bbcce8e841e432d25df8f2ad1b6258e06441a3bdf"
	expectedBlockNumber = uint64(10764834) // 0xa44222
	// Beacon fields (slots 1/2/3/8/9), real in the pre-genesisRoot corpus.
	expectedPrevSyncCommittee = "4577257aad51ec8b4519e0ba0546f2a032b2534f87f811a19b27b4d42278787d"
	expectedSyncCommittee     = "4577257aad51ec8b4519e0ba0546f2a032b2534f87f811a19b27b4d42278787d"
	expectedNextSyncCommittee = "4293e591071f6fb96e4a99a578693578bf4a9125c17b20abb845d3861c248ee0"
	expectedPrevHead          = uint64(10154464) // 0x9af1e0
	expectedNewHead           = uint64(10154528) // 0x9af220
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// Golden decode of parseProvenFields against a REAL alloy-abi-encoded
// ProofOutputs blob — the only parser test that does. The other parser tests
// plant bytes at the same offset constant they read back, so a wrong offset
// shifts write and read together and goes undetected. The known-good values
// below are the sole non-circular anchor for those security-critical offsets.
//
// genesisRoot is intentionally NOT asserted: this is the pre-genesisRoot corpus,
// so slot 10 holds the old storageSlots offset pointer (0x…0160), not a real
// GVR. Add the assertion when the corpus is regenerated (plan C2). All other
// fields (slots 1/2/3/5/6/7/8/9) are real and asserted here.
func TestParseProvenFields_DecodesRealV6_1_0Corpus(t *testing.T) {
	pv := mustDecodeHex(t, v6_1_0_PublicValuesHex)
	pf, err := parseProvenFields(pv)
	if err != nil {
		t.Fatalf("unexpected error parsing real corpus: %v", err)
	}
	if pf.stateRoot != expectedStateRoot {
		t.Errorf("stateRoot = %q, want %q", pf.stateRoot, expectedStateRoot)
	}
	if pf.blockHash != expectedBlockHash {
		t.Errorf("blockHash = %q, want %q", pf.blockHash, expectedBlockHash)
	}
	if pf.blockNumber != expectedBlockNumber {
		t.Errorf("blockNumber = %d, want %d", pf.blockNumber, expectedBlockNumber)
	}
	if pf.prevSyncCommittee != expectedPrevSyncCommittee {
		t.Errorf("prevSyncCommittee = %q, want %q", pf.prevSyncCommittee, expectedPrevSyncCommittee)
	}
	if pf.syncCommittee != expectedSyncCommittee {
		t.Errorf("syncCommittee = %q, want %q", pf.syncCommittee, expectedSyncCommittee)
	}
	if pf.nextSyncCommittee != expectedNextSyncCommittee {
		t.Errorf("nextSyncCommittee = %q, want %q", pf.nextSyncCommittee, expectedNextSyncCommittee)
	}
	if pf.prevHead != expectedPrevHead {
		t.Errorf("prevHead = %d, want %d", pf.prevHead, expectedPrevHead)
	}
	if pf.newHead != expectedNewHead {
		t.Errorf("newHead = %d, want %d", pf.newHead, expectedNewHead)
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
			pv := make([]byte, tt.size)
			if tt.size >= 32 {
				pv[31] = byte(PvAbiOffset) // valid offset so length is the only failure mode
			}
			_, err := parseProvenFields(pv)
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
	pv := make([]byte, PvMinLen)
	// Build a fully-sized buffer but with a wrong offset prefix.
	pv[31] = 0x40

	_, err := parseProvenFields(pv)
	if err == nil {
		t.Fatal("expected error for non-32 ABI offset, got none")
	}
	if err.Symbol != ce.ErrInput {
		t.Errorf("symbol = %q, want ErrInput", err.Symbol)
	}
}

// Boundary decode at exactly PvMinLen with a planted blockNumber + genesisRoot,
// confirming the parser reads the last field (genesisRoot, slot 10) in-bounds.
func TestParseProvenFields_BoundaryAtMinLen(t *testing.T) {
	pv := make([]byte, PvMinLen)
	pv[31] = byte(PvAbiOffset) // offset = 32
	pv[PvFieldBlockNumber+31] = 0x42
	pv[PvFieldGenesisRoot+31] = 0xab // last byte of the genesisRoot slot

	pf, err := parseProvenFields(pv)
	if err != nil {
		t.Fatalf("unexpected error at PvMinLen boundary: %v", err)
	}
	if pf.blockNumber != 0x42 {
		t.Errorf("blockNumber = %d, want 0x42", pf.blockNumber)
	}
	want := "00000000000000000000000000000000000000000000000000000000000000ab"
	if pf.genesisRoot != want {
		t.Errorf("genesisRoot = %q, want %q", pf.genesisRoot, want)
	}
}

// W4 Cluster B HIGH #22: sanity test on the looksLikeBlockHash shape
// check used by initContract to reject obviously-malformed anchors.
func TestLooksLikeBlockHash(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"0x0000000000000000000000000000000000000000000000000000000000000000", true},
		{"0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", true},
		{"0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", true},
		{"", false},
		{"0x", false},
		{"0xabcd", false},   // too short
		{"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", false}, // no 0x prefix
		{"0xZZZ_def0123456789abcdef0123456789abcdef0123456789abcdef0123456789", false}, // non-hex char
	}
	for _, tt := range tests {
		if got := looksLikeBlockHash(tt.s); got != tt.want {
			t.Errorf("looksLikeBlockHash(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}
