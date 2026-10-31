package main

import (
	"encoding/json"
	"strings"
	"testing"

	"zk-header-verifier/sdk"
)

func call(f func(*string) *string, payload any) (msg string) {
	b, _ := json.Marshal(payload)
	s := string(b)
	defer func() {
		if r := recover(); r != nil {
			msg, _ = r.(string)
			if msg == "" {
				msg = "abort"
			}
		}
	}()
	f(&s)
	return ""
}

// Z-1: devSetHeader plants a header with no proof. Anyone could call it once
// init had set the sentinel (and anyone can call init), so a mock deployed by
// mistake and wired as a bridge's verifier let anyone forge deposits. Only the
// mock's owner with active authority may plant.
func TestZ1_OnlyTheOwnerPlantsHeaders(t *testing.T) {
	sdk.ResetTestState()
	sdk.SetTestHaltOnAbort(true)
	t.Cleanup(sdk.ResetTestState)
	root := strings.Repeat("ab", 32)
	plant := map[string]any{"block_number": 7, "state_root": root, "tx_root": root, "receipts_root": root, "chain_id": 11155111}
	stored := func() bool { v := sdk.StateGetObject("b-7"); return v != nil && *v != "" }

	sdk.SetTestCaller("hive:mallory")
	if msg := call(initContract, map[string]any{}); msg != "" {
		t.Fatalf("init: %s", msg)
	}
	if msg := call(devSetHeader, plant); !strings.Contains(msg, "owner required") || stored() {
		t.Fatalf("devSetHeader by a non-owner after init = %q (stored %v), want refused", msg, stored())
	}
	sdk.SetTestEnvJSON(`{"contract.id":"contract:test","msg.caller":"hive:owner","msg.sender":"hive:owner","msg.required_auths":[],"msg.required_posting_auths":["hive:owner"]}`)
	if msg := call(devSetHeader, plant); !strings.Contains(msg, "active authority") || stored() {
		t.Fatalf("devSetHeader with the owner's posting key = %q (stored %v), want refused", msg, stored())
	}
	sdk.SetTestCaller("hive:owner")
	if msg := call(devSetHeader, plant); msg != "" || !stored() {
		t.Fatalf("devSetHeader by the owner = %q (stored %v), want the header planted", msg, stored())
	}
}
