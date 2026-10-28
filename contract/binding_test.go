package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"zk-header-verifier/sdk"
)

// submitProof's gates, one by one: a valid proof is only accepted for this
// chain (genesis), from the stored head and its trusted committee, moving
// forward, and with the headers it proves. Across's SP1Helios tests the same
// properties (update from a missing/old/behind head, wrong committee, several
// committee periods).

// proofOut is a test ProofOutputs; zero committee/genesis bytes take the
// defaults setupVerifier trusts (committee 0x22, genesis 0x11).
type proofOut struct {
	prevHead, newHead              uint64
	prevCommittee, committee, next byte
	genesis                        byte
	tip                            testHeader
}

func (p proofOut) publicValues() string {
	or := func(b, d byte) byte {
		if b == 0 {
			return d
		}
		return b
	}
	var pv []byte
	pv = append(pv, word(32)...)
	pv = append(pv, fill(0x01)...)
	pv = append(pv, word(p.prevHead)...)
	pv = append(pv, fill(or(p.prevCommittee, 0x22))...)
	pv = append(pv, word(p.newHead)...)
	pv = append(pv, fill(0x03)...)
	pv = append(pv, p.tip.stateRoot[:]...)
	pv = append(pv, p.tip.hash[:]...)
	pv = append(pv, word(p.tip.number)...)
	pv = append(pv, fill(or(p.committee, 0x22))...)
	pv = append(pv, fill(or(p.next, 0xff))...)
	pv = append(pv, fill(or(p.genesis, 0x11))...)
	return hex.EncodeToString(pv)
}

func (p proofOut) payload(batch []testHeader) map[string]any {
	return map[string]any{"proof": "ab", "public_values": p.publicValues(), "headers": headersJSON(batch)}
}

// snapshot is the verifier state a refused proof must leave alone.
func snapshot() string {
	var b strings.Builder
	for _, k := range []string{KeyBeaconHead, KeyLastHeight, KeyLastBlockHash, SyncCommitteePrefix + "1", SyncCommitteePrefix + "2"} {
		v := sdk.StateGetObject(k)
		if v != nil {
			b.WriteString(k + "=" + *v + ";")
		}
	}
	return b.String()
}

func TestBinding_EachGateRefusesAndChangesNothing(t *testing.T) {
	anchor := [32]byte{0xa1}
	batch := testChain(101, 3, anchor, 0)
	ok := proofOut{prevHead: 8192, newHead: 8224, tip: batch[2]}
	other := testChain(101, 3, anchor, 9) // same numbers, different contents
	// Linked by parent hash but skipping block 102 (only a forged header can).
	jumped := append(testChain(101, 1, anchor, 0), testChain(103, 1, batch[0].hash, 0)...)
	for _, c := range []struct {
		name  string
		p     proofOut
		batch []testHeader
		setup func()
		want  string
	}{
		{"proof fails to verify", ok, batch, func() { sdk.SetTestSp1Verdict(false) }, "proof verification failed"},
		{"another chain's proof (genesis)", proofOut{prevHead: 8192, newHead: 8224, tip: batch[2], genesis: 0x12}, batch, nil, "does not match verifier's bound chain"},
		{"untrusted start committee", proofOut{prevHead: 8192, newHead: 8224, tip: batch[2], prevCommittee: 0x23}, batch, nil, "is not trusted"},
		{"no committee for the start period", ok, batch, func() { sdk.StateDeleteObject(SyncCommitteePrefix + "1") }, "no trusted sync committee"},
		{"head does not advance", proofOut{prevHead: 8192, newHead: 8192, tip: batch[2]}, batch, nil, "not advancing"},
		{"head moves back", proofOut{prevHead: 8192, newHead: 8160, tip: batch[2]}, batch, nil, "not advancing"},
		{"last header is not the proven block", ok, append(append([]testHeader{}, batch[:2]...), other[2]), nil, "!= proven block hash"},
		{"proven number differs from the header", proofOut{prevHead: 8192, newHead: 8224, tip: testHeader{number: 104, hash: batch[2].hash, stateRoot: batch[2].stateRoot}}, batch, nil, "block number"},
		{"proven state root differs from the header", proofOut{prevHead: 8192, newHead: 8224, tip: testHeader{number: 103, hash: batch[2].hash, stateRoot: [32]byte{0xee}}}, batch, nil, "state_root"},
		{"an earlier header is not the parent", ok, []testHeader{other[0], batch[1], batch[2]}, nil, "hash chain broken"},
		{"a gap in the batch", ok, []testHeader{batch[0], batch[2]}, nil, "hash chain broken"},
		{"linked headers that skip a number", proofOut{prevHead: 8192, newHead: 8224, tip: jumped[1]}, jumped, nil, "hash chain broken"},
		{"the proven block is not above the tip", ok, batch, func() { sdk.StateSetObject(KeyLastHeight, "103") }, "does not advance the stored tip"},
	} {
		t.Run(c.name, func(t *testing.T) {
			setupVerifier(t, 100, anchor)
			if c.setup != nil {
				c.setup()
			}
			before := snapshot()
			if msg := call(submitProof, c.p.payload(c.batch)); !strings.Contains(msg, c.want) {
				t.Fatalf("submitProof = %q, want refused with %q", msg, c.want)
			}
			if after := snapshot(); after != before || stored(101) || stored(103) {
				t.Fatalf("a refused proof changed state: %s -> %s (stored 101 %v, 103 %v)", before, after, stored(101), stored(103))
			}
		})
	}
	// The same payload with nothing changed is accepted.
	setupVerifier(t, 100, anchor)
	if msg := call(submitProof, ok.payload(batch)); msg != "" || getBeaconHead() != 8224 || getLastHeight() != 103 || !stored(103) {
		t.Fatalf("the valid proof: %q, head %d tip %d stored %v", msg, getBeaconHead(), getLastHeight(), stored(103))
	}
}

// A landed proof cannot be submitted again: the head has moved past its start.
func TestBinding_ALandedProofCannotBeReplayed(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupVerifier(t, 100, anchor)
	batch := testChain(101, 3, anchor, 0)
	p := proofOut{prevHead: 8192, newHead: 8224, tip: batch[2]}.payload(batch)
	if msg := call(submitProof, p); msg != "" {
		t.Fatal(msg)
	}
	before := snapshot()
	if msg := call(submitProof, p); !strings.Contains(msg, "not advancing") && !strings.Contains(msg, "does not continue") {
		t.Fatalf("replay = %q, want refused", msg)
	}
	if snapshot() != before {
		t.Fatal("the replay changed state")
	}
}

// Committee rotation: a proof's next committee becomes the trusted committee
// of the next period, and a proof starting in that period must start from it.
func TestBinding_RotatesThroughCommitteePeriods(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupVerifier(t, 100, anchor)
	a := testChain(101, 1, anchor, 0)
	if msg := call(submitProof, proofOut{prevHead: 8192, newHead: 16352, next: 0x33, tip: a[0]}.payload(a)); msg != "" {
		t.Fatalf("proof with a next committee: %s", msg)
	}
	if v := sdk.StateGetObject(SyncCommitteePrefix + "2"); v == nil || *v != strings.Repeat("33", 32) {
		t.Fatalf("period 2 committee = %v, want the proven next committee", v)
	}
	// Across the period boundary: starts in period 1 (0x22), ends in period 2.
	b := testChain(102, 1, a[0].hash, 0)
	if msg := call(submitProof, proofOut{prevHead: 16352, newHead: 16416, committee: 0x33, next: 0x44, tip: b[0]}.payload(b)); msg != "" {
		t.Fatalf("proof into period 2: %s", msg)
	}
	c := testChain(103, 1, b[0].hash, 0)
	if msg := call(submitProof, proofOut{prevHead: 16416, newHead: 16448, committee: 0x33, next: 0x44, tip: c[0]}.payload(c)); !strings.Contains(msg, "is not trusted") {
		t.Fatalf("a period-2 proof starting from the period-1 committee = %q, want refused", msg)
	}
	if msg := call(submitProof, proofOut{prevHead: 16416, newHead: 16448, prevCommittee: 0x33, committee: 0x33, next: 0x44, tip: c[0]}.payload(c)); msg != "" {
		t.Fatalf("a period-2 proof from the period-2 committee: %s", msg)
	}
	if v := sdk.StateGetObject(SyncCommitteePrefix + "3"); v == nil || *v != strings.Repeat("44", 32) {
		t.Fatalf("period 3 committee = %v", v)
	}
}
