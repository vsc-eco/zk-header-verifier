package main

import (
	"math"
	"strconv"
	"testing"

	"zk-header-verifier/sdk"
)

// A retention near 2^64 ("keep everything") must still store backfilled
// headers; BlockNumber+maxRetention wrapped and dropped them.
func TestE5_HugeRetentionStillStoresTheBackfill(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupGapVerifier(t, 100, anchor)
	sdk.StateSetObject(KeyMaxRetention, strconv.FormatUint(math.MaxUint64, 10))
	chain := testChain(101, 40, anchor, 0)
	if msg := call(submitProof, proveTip(chain[28:])); msg != "" {
		t.Fatalf("tip batch: %s", msg)
	}
	if msg := call(submitHeaders, map[string]any{"headers": headersJSON(chain[16:28])}); msg != "" {
		t.Fatalf("backfill: %s", msg)
	}
	if !stored(128) || !stored(117) {
		t.Fatalf("backfilled heights not stored with a huge retention: b-128 %v b-117 %v", stored(128), stored(117))
	}
}
