package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"zk-header-verifier/sdk"

	"golang.org/x/crypto/sha3"
)

// E5: a proof's batch holds at most MaxHeadersPerTx headers but ~32 blocks lie
// between finalized checkpoints, and submitProof required the batch to reach the
// stored chain, so no proof after the first could land. A batch that does not
// reach it now opens a gap that submitHeaders backfills.

func rlpBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(rlpHead(0x80, len(b)), b...)
}

func rlpHead(base byte, n int) []byte {
	if n < 56 {
		return []byte{base + byte(n)}
	}
	l := new([8]byte)
	binary.BigEndian.PutUint64(l[:], uint64(n))
	i := 0
	for i < 7 && l[i] == 0 {
		i++
	}
	return append([]byte{base + 55 + byte(8-i)}, l[i:]...)
}

func rlpUint(v uint64) []byte {
	if v == 0 {
		return rlpBytes(nil)
	}
	b := new([8]byte)
	binary.BigEndian.PutUint64(b[:], v)
	i := 0
	for b[i] == 0 {
		i++
	}
	return rlpBytes(b[i:])
}

func rlpList(items ...[]byte) []byte {
	var body []byte
	for _, it := range items {
		body = append(body, it...)
	}
	return append(rlpHead(0xc0, len(body)), body...)
}

func keccak(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

type testHeader struct {
	number    uint64
	rlp       []byte
	hash      [32]byte
	stateRoot [32]byte
}

// testChain builds headers from..from+n-1 on top of parent; salt tells forks apart.
func testChain(from uint64, n int, parent [32]byte, salt byte) []testHeader {
	out := make([]testHeader, 0, n)
	for i := 0; i < n; i++ {
		num := from + uint64(i)
		root := [32]byte{salt, byte(num), byte(num >> 8)}
		z := func(n int) []byte { return make([]byte, n) }
		r := rlpList(rlpBytes(parent[:]), rlpBytes(z(32)), rlpBytes(z(20)), rlpBytes(root[:]), rlpBytes(root[:]), rlpBytes(root[:]),
			rlpBytes(z(256)), rlpUint(0), rlpUint(num), rlpUint(30_000_000), rlpUint(0), rlpUint(1_700_000_000+num*12),
			rlpBytes(nil), rlpBytes(z(32)), rlpBytes(z(8)), rlpUint(1_000_000_000))
		h := testHeader{number: num, rlp: r, hash: keccak(r), stateRoot: root}
		out = append(out, h)
		parent = h.hash
	}
	return out
}

func word(v uint64) []byte {
	w := make([]byte, 32)
	binary.BigEndian.PutUint64(w[24:], v)
	return w
}

func fill(b byte) []byte {
	w := make([]byte, 32)
	for i := range w {
		w[i] = b
	}
	return w
}

// testPublicValues is an ABI-encoded ProofOutputs proving block tip, advancing
// the beacon head from prevHead to newHead inside sync period 1.
func testPublicValues(prevHead, newHead uint64, tip testHeader) string {
	var pv []byte
	pv = append(pv, word(32)...)         // tuple offset
	pv = append(pv, fill(0x01)...)       // prevHeader
	pv = append(pv, word(prevHead)...)   // prevHead
	pv = append(pv, fill(0x22)...)       // prevSyncCommitteeHash (trusted)
	pv = append(pv, word(newHead)...)    // newHead
	pv = append(pv, fill(0x03)...)       // newHeader
	pv = append(pv, tip.stateRoot[:]...) // executionStateRoot
	pv = append(pv, tip.hash[:]...)      // executionBlockHash
	pv = append(pv, word(tip.number)...) // executionBlockNumber
	pv = append(pv, fill(0x22)...)       // syncCommitteeHash (same period)
	pv = append(pv, fill(0xff)...)       // nextSyncCommitteeHash: none
	pv = append(pv, fill(0x11)...)       // genesisRoot
	return hex.EncodeToString(pv)
}

func setupGapVerifier(t *testing.T, lastHeight uint64, anchor [32]byte) {
	t.Helper()
	sdk.ResetTestState()
	sdk.SetTestHaltOnAbort(true)
	sdk.SetTestSp1Verdict(true)
	for k, v := range map[string]string{
		KeyGroth16Vk: "aa", KeyVkRoot: "bb", KeySp1VkeyHash: "cc",
		KeyLastBlockHash: "0x" + hex.EncodeToString(anchor[:]), KeyLastHeight: strconv.FormatUint(lastHeight, 10),
		KeyGenesisRoot: strings.Repeat("11", 32), KeyBeaconHead: "8192", SyncCommitteePrefix + "1": strings.Repeat("22", 32),
		KeyExpectedChainId: "11155111", KeyMaxRetention: "50400",
	} {
		sdk.StateSetObject(k, v)
	}
	t.Cleanup(sdk.ResetTestState)
}

func headersJSON(hs []testHeader) []map[string]string {
	out := make([]map[string]string, len(hs))
	for i, h := range hs {
		out[i] = map[string]string{"rlp_hex": hex.EncodeToString(h.rlp)}
	}
	return out
}

// call runs a handler and returns its abort message ("" when it returned).
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

// proveTip is a submitProof payload for batch, continuing the stored beacon head.
func proveTip(batch []testHeader) map[string]any {
	head := getBeaconHead()
	return map[string]any{"proof": "ab", "public_values": testPublicValues(head, head+32, batch[len(batch)-1]), "headers": headersJSON(batch)}
}

func stored(n uint64) bool {
	return sdk.StateGetObject(KeyBlockPrefix+strconv.FormatUint(n, 10)) != nil
}

// wantHeader is h as stored for account-mapping, labelled Sepolia.
func wantHeader(h testHeader) string {
	b := []byte{HeaderVersionV1}
	b = appendUint64(b, h.number)
	for i := 0; i < 3; i++ {
		b = append(b, h.stateRoot[:]...)
	}
	for _, v := range []uint64{1_000_000_000, 30_000_000, 1_700_000_000 + h.number*12, 11155111} {
		b = appendUint64(b, v)
	}
	return string(b)
}

func TestE5_ProofPastTheBatchLimitOpensAGapThatBackfillCloses(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupGapVerifier(t, 100, anchor)
	chain := testChain(101, 40, anchor, 0) // 101..140

	if msg := call(submitProof, proveTip(chain[28:])); msg != "" { // 129..140
		t.Fatalf("submitProof for a batch 28 blocks past the stored chain: %s", msg)
	}
	if !stored(140) || !stored(129) || stored(128) || getLastHeight() != 140 {
		t.Fatalf("after the tip batch: b-140 %v b-129 %v b-128 %v h=%d", stored(140), stored(129), stored(128), getLastHeight())
	}
	if msg := call(submitProof, proveTip(testChain(141, 1, chain[39].hash, 0))); !strings.Contains(msg, "gap is open") {
		t.Fatalf("a second proof with the gap open = %q, want refused", msg)
	}
	for _, batch := range [][]testHeader{chain[16:28], chain[4:16], chain[0:4]} {
		if msg := call(submitHeaders, map[string]any{"headers": headersJSON(batch)}); msg != "" {
			t.Fatalf("backfill %d..%d: %s", batch[0].number, batch[len(batch)-1].number, msg)
		}
	}
	for _, h := range chain {
		if got := sdk.StateGetObject(KeyBlockPrefix + strconv.FormatUint(h.number, 10)); got == nil || *got != wantHeader(h) {
			t.Fatalf("b-%d after the backfill is not the header as submitProof stores it", h.number)
		}
	}
	if sdk.StateGetObject(KeyGapWant) != nil || sdk.StateGetObject(KeyGapLow) != nil {
		t.Fatal("the gap is still open after the backfill met the stored chain")
	}
	// The next proof continues from the tip.
	if msg := call(submitProof, proveTip(testChain(141, 3, chain[39].hash, 0))); msg != "" {
		t.Fatalf("the next contiguous proof after the gap closed: %s", msg)
	}
}

func TestE5_BackfillOnlyAcceptsTheProvenChain(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupGapVerifier(t, 100, anchor)
	chain := testChain(101, 30, anchor, 0)                         // 101..130
	if msg := call(submitProof, proveTip(chain[18:])); msg != "" { // 119..130
		t.Fatal(msg)
	}
	other := testChain(101, 30, anchor, 9) // same heights, different blocks
	for _, tc := range []struct {
		name, want string
		batch      []testHeader
	}{
		{"not the wanted parent", "not the parent of the lowest", other[6:18]},
		{"chain broken in the batch", "hash chain broken at block 112", append(append([]testHeader{}, other[6:12]...), chain[12:18]...)},
		{"skips a height", "hash chain broken at block 111", append(append([]testHeader{}, chain[6:11]...), chain[12:18]...)},
		{"too many headers", "headers required", chain[5:18]},
	} {
		if msg := call(submitHeaders, map[string]any{"headers": headersJSON(tc.batch)}); !strings.Contains(msg, tc.want) {
			t.Errorf("%s: backfill = %q, want %q", tc.name, msg, tc.want)
		}
	}
	if stored(118) {
		t.Fatal("a refused backfill stored a header")
	}
}

func TestE5_BackfillCannotOvershootTheStoredChain(t *testing.T) {
	chain := testChain(95, 46, [32]byte{0xa0}, 0) // 95..140; 95..100 already stored
	setupGapVerifier(t, 100, chain[5].hash)
	if msg := call(submitProof, proveTip(chain[34:])); msg != "" { // 129..140
		t.Fatal(msg)
	}
	for _, batch := range [][]testHeader{chain[22:34], chain[10:22]} { // 105..128
		if msg := call(submitHeaders, map[string]any{"headers": headersJSON(batch)}); msg != "" {
			t.Fatal(msg)
		}
	}
	// 99..104 is the real chain but reaches into the stored one: accepting it
	// would leave no batch that can start at 101 and close the gap.
	for _, over := range [][]testHeader{chain[4:10], chain[5:10]} { // 99..104, 100..104
		if msg := call(submitHeaders, map[string]any{"headers": headersJSON(over)}); !strings.Contains(msg, "below the stored chain") {
			t.Fatalf("backfill %d..104 = %q, want refused", over[0].number, msg)
		}
	}
	if msg := call(submitHeaders, map[string]any{"headers": headersJSON(chain[6:10])}); msg != "" {
		t.Fatalf("101..104 after a refused overshoot: %s", msg)
	}
	if sdk.StateGetObject(KeyGapWant) != nil {
		t.Fatal("gap still open")
	}
}

func TestE5_BackfillThatDoesNotMeetTheStoredChainFailsClosed(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupGapVerifier(t, 100, anchor)
	fork := testChain(101, 20, [32]byte{0xbe, 0xef}, 3) // does not descend from the stored tip
	if msg := call(submitProof, proveTip(fork[8:])); msg != "" {
		t.Fatal(msg)
	}
	if msg := call(submitHeaders, map[string]any{"headers": headersJSON(fork[0:8])}); !strings.Contains(msg, "does not meet the stored chain") {
		t.Fatalf("backfill reaching the stored tip on another chain = %q, want refused", msg)
	}
	if sdk.StateGetObject(KeyGapWant) == nil {
		t.Fatal("the gap must stay open (fail closed)")
	}
}

func TestE5_ContiguousProofIsUnchanged(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupGapVerifier(t, 100, anchor)
	chain := testChain(101, 12, anchor, 0)
	if msg := call(submitProof, proveTip(chain)); msg != "" {
		t.Fatal(msg)
	}
	if sdk.StateGetObject(KeyGapWant) != nil || getLastHeight() != 112 || !stored(101) {
		t.Fatalf("a contiguous batch opened a gap or stored nothing: h=%d", getLastHeight())
	}
	if msg := call(submitHeaders, map[string]any{"headers": headersJSON(testChain(90, 2, anchor, 0))}); !strings.Contains(msg, "no header gap") {
		t.Fatalf("submitHeaders with no gap = %q", msg)
	}
	// A batch that overlaps the stored chain without linking to it is still refused.
	setupGapVerifier(t, 100, anchor)
	if msg := call(submitProof, proveTip(testChain(101, 12, [32]byte{0x99}, 0))); !strings.Contains(msg, "does not match stored anchor") {
		t.Fatalf("a batch at the stored tip+1 with the wrong parent = %q", msg)
	}
}

func TestE5_BackfillKeepsTheRetentionWindow(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupGapVerifier(t, 100, anchor)
	sdk.StateSetObject(KeyMaxRetention, "12")
	for n := uint64(91); n <= 100; n++ {
		sdk.StateSetObject(KeyBlockPrefix+strconv.FormatUint(n, 10), "x")
	}
	chain := testChain(101, 40, anchor, 0)
	if msg := call(submitProof, proveTip(chain[28:])); msg != "" {
		t.Fatal(msg)
	}
	for _, batch := range [][]testHeader{chain[16:28], chain[4:16], chain[0:4]} {
		if msg := call(submitHeaders, map[string]any{"headers": headersJSON(batch)}); msg != "" {
			t.Fatal(msg)
		}
	}
	// Tip 140, retention 12: exactly 129..140 remain, as with contiguous
	// proofs; 128, the top backfilled height, is the first one outside.
	for n := uint64(91); n <= 140; n++ {
		if stored(n) != (n > 128) {
			t.Errorf("b-%d stored=%v, want %v", n, stored(n), n > 128)
		}
	}
	if sdk.StateGetObject(KeyGapWant) != nil {
		t.Fatal("headers outside retention must still link the gap closed")
	}
}
