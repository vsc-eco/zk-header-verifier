package main

import (
	"strings"
	"testing"

	"zk-header-verifier/sdk"
)

// Pre-merge review (2026-10-22): the RV-4, A2 and B13 gates had no test (a
// mutation deleting each left the suite green).

// initParams is a valid initContract payload anchored at block 100.
func initParams(anchor string, retention uint64) map[string]any {
	return map[string]any{
		"groth16_vk": "aa", "vk_root": "bb", "sp1_vkey_hash": "cc",
		"max_retention": retention, "initial_height": 100, "initial_block_hash": anchor,
		"expected_chain_id": 11155111, "genesis_root": strings.Repeat("11", 32),
		"initial_sync_committee_hash": strings.Repeat("22", 32), "initial_head": 8192,
	}
}

func freshVerifier(t *testing.T) {
	t.Helper()
	sdk.ResetTestState()
	sdk.SetTestHaltOnAbort(true)
	sdk.SetTestSp1Verdict(true)
	t.Cleanup(sdk.ResetTestState)
}

// withNextCommittee is pv with its nextSyncCommitteeHash word replaced.
func withNextCommittee(pv string, next string) string {
	const at = 2 * (32 + 9*32) // hex offset of ABI slot 9 after the tuple offset
	return pv[:at] + next + pv[at+64:]
}

// RV-4: a proof must start from the stored beacon head, not from any slot
// whose committee happens to be trusted.
func TestRV4_ProofMustContinueTheStoredBeaconHead(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupGapVerifier(t, 100, anchor)
	batch := testChain(101, 3, anchor, 0)
	head := getBeaconHead()
	skip := map[string]any{"proof": "ab", "public_values": testPublicValues(head+32, head+64, batch[2]), "headers": headersJSON(batch)}
	if msg := call(submitProof, skip); !strings.Contains(msg, "does not continue the stored beacon head") {
		t.Fatalf("a proof starting past the stored head = %q, want refused", msg)
	}
	if msg := call(submitProof, proveTip(batch)); msg != "" {
		t.Fatalf("the proof from the stored head: %s", msg)
	}
}

// RV-4: a proof may not overwrite an already trusted committee; the same hash
// is a no-op and "no next committee" is never stored.
func TestRV4_TrustedCommitteeIsNeverOverwritten(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupGapVerifier(t, 100, anchor)
	sdk.StateSetObject(SyncCommitteePrefix+"2", strings.Repeat("33", 32))
	batch := testChain(101, 3, anchor, 0)
	p := proveTip(batch)
	p["public_values"] = withNextCommittee(p["public_values"].(string), strings.Repeat("44", 32))
	if msg := call(submitProof, p); !strings.Contains(msg, "already trusted and differs") {
		t.Fatalf("a proof replacing period 2's committee = %q, want refused", msg)
	}
	if got := sdk.StateGetObject(SyncCommitteePrefix + "2"); got == nil || *got != strings.Repeat("33", 32) {
		t.Fatalf("period 2's committee changed: %v", got)
	}
	// The stub does not roll state back on an abort (the runtime does), so the
	// accepted case starts from a fresh verifier.
	setupGapVerifier(t, 100, anchor)
	sdk.StateSetObject(SyncCommitteePrefix+"2", strings.Repeat("33", 32))
	p = proveTip(batch)
	p["public_values"] = withNextCommittee(p["public_values"].(string), strings.Repeat("33", 32))
	if msg := call(submitProof, p); msg != "" {
		t.Fatalf("a proof carrying the same trusted committee: %s", msg)
	}
	if sdk.StateGetObject(SyncCommitteePrefix+"3") != nil {
		t.Fatal("a committee was stored for a period the proof did not name")
	}
}

// A2: the owner's posting key (Caller, but not in RequiredAuths) cannot use
// owner actions; the owner's active key can.
func TestA2_OwnerPostingKeyCannotPinTheElfHash(t *testing.T) {
	freshVerifier(t)
	pin := map[string]string{"hash": strings.Repeat("ab", 32)}
	sdk.SetTestEnvJSON(`{"contract.id":"contract:test","msg.caller":"hive:owner","msg.sender":"hive:owner","msg.required_auths":[],"msg.required_posting_auths":["hive:owner"]}`)
	if msg := call(setExpectedElfHash, pin); !strings.Contains(msg, "active authority") {
		t.Fatalf("setExpectedElfHash signed with the owner's posting key = %q, want refused", msg)
	}
	sdk.SetTestCaller("hive:mallory")
	if msg := call(setExpectedElfHash, pin); !strings.Contains(msg, "owner required") {
		t.Fatalf("setExpectedElfHash by a non-owner = %q, want refused", msg)
	}
	sdk.SetTestCaller("hive:owner")
	if msg := call(setExpectedElfHash, pin); msg != "" {
		t.Fatalf("setExpectedElfHash with the owner's active key: %s", msg)
	}
}

// B13: init refuses a retention under a day and defaults to a week.
func TestB13_RetentionFloorAndDefault(t *testing.T) {
	anchor := "0x" + strings.Repeat("a1", 32)
	for _, tc := range []struct {
		retention uint64
		refused   bool
		stored    string
	}{{MinMaxRetention - 1, true, ""}, {MinMaxRetention, false, "7200"}, {0, false, "50400"}} {
		freshVerifier(t)
		msg := call(initContract, initParams(anchor, tc.retention))
		if tc.refused {
			if !strings.Contains(msg, "max_retention must be at least") {
				t.Fatalf("max_retention %d = %q, want refused", tc.retention, msg)
			}
			continue
		}
		if msg != "" {
			t.Fatalf("max_retention %d: %s", tc.retention, msg)
		}
		if got := sdk.StateGetObject(KeyMaxRetention); got == nil || *got != tc.stored {
			t.Fatalf("max_retention %d stored as %v, want %s", tc.retention, got, tc.stored)
		}
	}
}
