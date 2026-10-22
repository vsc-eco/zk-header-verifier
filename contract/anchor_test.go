package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"zk-header-verifier/sdk"
)

// An uppercase initial_block_hash is stored in the form submitProof compares,
// so the first contiguous proof links to it.
func TestInit_UppercaseAnchorStillLinks(t *testing.T) {
	freshVerifier(t)
	anchor := [32]byte{0xab, 0xcd, 0xef}
	upper := "0X" + strings.ToUpper(hex.EncodeToString(anchor[:]))
	if msg := call(initContract, initParams(upper, 0)); msg != "" {
		t.Fatalf("init with an uppercase anchor: %s", msg)
	}
	if got := sdk.StateGetObject(KeyLastBlockHash); got == nil || *got != "0x"+hex.EncodeToString(anchor[:]) {
		t.Fatalf("anchor stored as %v, want lowercase 0x hex", got)
	}
	if msg := call(submitProof, proveTip(testChain(101, 3, anchor, 0))); msg != "" {
		t.Fatalf("the first proof on an uppercase anchor: %s", msg)
	}
}
