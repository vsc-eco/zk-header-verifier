package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"zk-header-verifier/sdk"
)

// RP-9: a proof stores only its own batch, with no backfill. Any other header
// is stored on demand from an EIP-2935 storage proof (attestHistoryRoot +
// attestHeaders) or linked down by parent hash from a stored one (submitHeaders).
// RP-6: a stored header lives max_retention blocks of the proven tip from when it
// was stored.

func parentOf(n uint64) string {
	v := sdk.StateGetObject(KeyParentPrefix + strconv.FormatUint(n, 10))
	if v == nil {
		return ""
	}
	return hex.EncodeToString([]byte(*v))
}

func TestRP9_ProofStoresItsBatchAndNeedsNoBackfill(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupVerifier(t, 100, anchor)
	chain := testChain(101, 200, anchor, 0) // 101..300

	if msg := call(submitProof, proveTip(chain[28:40])); msg != "" { // 129..140, far above the tip
		t.Fatalf("a batch 28 blocks above the stored tip: %s", msg)
	}
	if getLastHeight() != 140 || !stored(129) || !stored(140) || stored(128) {
		t.Fatalf("h=%d b-129 %v b-140 %v b-128 %v", getLastHeight(), stored(129), stored(140), stored(128))
	}
	if parentOf(129) != hex.EncodeToString(chain[27].hash[:]) {
		t.Fatal("ph-129 is not block 128's hash")
	}
	// Old code: refused "a header gap is open" until 101..128 were backfilled.
	if msg := call(submitProof, proveTip(chain[199:200])); msg != "" { // 300 alone
		t.Fatalf("the next proof without any backfill: %s", msg)
	}
	if getLastHeight() != 300 || !stored(300) || stored(299) {
		t.Fatalf("after the second proof h=%d", getLastHeight())
	}
	// The tip never moves back, and the batch must still hash into the proof.
	if msg := call(submitProof, proveTip(chain[150:151])); !strings.Contains(msg, "does not advance the stored tip") {
		t.Fatalf("a proof below the tip = %q", msg)
	}
	bad := proveTip(chain[200-3 : 200])
	bad["headers"] = headersJSON(append(append([]testHeader{}, testChain(298, 1, [32]byte{9}, 7)...), chain[198:200]...))
	if msg := call(submitProof, bad); !strings.Contains(msg, "hash chain broken at block 298") {
		t.Fatalf("a batch that does not hash into the proven block = %q", msg)
	}
	stored := sdk.StateGetObject(KeyBlockPrefix + "140")
	if stored == nil || *stored != wantHeader(chain[39]) {
		t.Fatal("b-140 is not the header as account-mapping reads it")
	}
}

func TestRP9_SubmitHeadersLinksDownFromAStoredHeader(t *testing.T) {
	anchor := [32]byte{0xa1}
	setupVerifier(t, 100, anchor)
	chain := testChain(101, 40, anchor, 0)                         // 101..140
	if msg := call(submitProof, proveTip(chain[34:])); msg != "" { // 135..140
		t.Fatal(msg)
	}
	other := testChain(101, 40, anchor, 9) // same heights, other blocks
	for _, tc := range []struct {
		name, want string
		batch      []testHeader
	}{
		{"not the stored parent", "is not the stored parent", other[28:34]},
		{"no stored header above", "is not the stored parent", chain[20:26]},
		{"broken inside", "hash chain broken at block 131", append(append([]testHeader{}, other[28:31]...), chain[31:34]...)},
		{"skips a height", "hash chain broken at block 129", append(append([]testHeader{}, chain[28:29]...), chain[30:34]...)},
		{"too many", "headers required", chain[21:34]},
	} {
		if msg := call(submitHeaders, map[string]any{"headers": headersJSON(tc.batch)}); !strings.Contains(msg, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, msg, tc.want)
		}
	}
	if stored(134) {
		t.Fatal("a refused batch stored a header")
	}
	for _, b := range [][]testHeader{chain[28:34], chain[22:28]} { // 129..134, then 123..128
		if msg := call(submitHeaders, map[string]any{"headers": headersJSON(b)}); msg != "" {
			t.Fatalf("link %d..%d: %s", b[0].number, b[len(b)-1].number, msg)
		}
	}
	for n := uint64(123); n <= 140; n++ {
		if got := sdk.StateGetObject(KeyBlockPrefix + strconv.FormatUint(n, 10)); got == nil || *got != wantHeader(chain[n-101]) {
			t.Fatalf("b-%d not stored as the proven chain", n)
		}
	}
	if getLastHeight() != 140 {
		t.Fatalf("submitHeaders moved the tip to %d", getLastHeight())
	}
}

// eip2935Fixture is real chain data (contract/testdata, fetched 2026-10-27 with
// eth_getProof and eth_getBlockByNumber): the history contract's account proof
// in the state of block root_block and three block headers with their storage
// proofs (root-1, root-100, root-8191, the window's ends).
type eip2935Fixture struct {
	Network      string   `json:"network"`
	RootBlock    uint64   `json:"root_block"`
	RootRLP      string   `json:"root_rlp"`
	StorageHash  string   `json:"storage_hash"`
	AccountProof []string `json:"account_proof"`
	Headers      []struct {
		Number       uint64   `json:"number"`
		Hash         string   `json:"hash"`
		RLP          string   `json:"rlp"`
		StorageProof []string `json:"storage_proof"`
	} `json:"headers"`
}

func loadFixture(t *testing.T, network string) eip2935Fixture {
	t.Helper()
	b, err := os.ReadFile("testdata/eip2935_" + network + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var f eip2935Fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func b64Nodes(t *testing.T, nodes []string) string {
	t.Helper()
	var all []byte
	for _, n := range nodes {
		b, err := hex.DecodeString(strings.TrimPrefix(n, "0x"))
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
	}
	return base64.StdEncoding.EncodeToString(all)
}

func bare(h string) string { return strings.TrimPrefix(h, "0x") }

// storeRoot stores f's root block as a proven tip would be.
func storeRoot(t *testing.T, f eip2935Fixture) {
	t.Helper()
	setupVerifier(t, f.RootBlock, [32]byte{1})
	storeVerifiedHeader(parseHeader(bare(f.RootRLP)), 11155111, f.RootBlock)
}

func attestItem(t *testing.T, rlp string, proof []string) map[string]string {
	return map[string]string{"rlp_hex": bare(rlp), "storage_proof": b64Nodes(t, proof)}
}

func TestRP9_AttestHeadersFromRealEIP2935Proofs(t *testing.T) {
	for _, network := range []string{"mainnet", "sepolia"} {
		t.Run(network, func(t *testing.T) {
			f := loadFixture(t, network)
			storeRoot(t, f)
			r := f.RootBlock

			if msg := call(attestHeaders, map[string]any{"root_block": r, "headers": []any{attestItem(t, f.Headers[0].RLP, f.Headers[0].StorageProof)}}); !strings.Contains(msg, "call attestHistoryRoot first") {
				t.Fatalf("attest before the history root = %q", msg)
			}
			if msg := call(attestHistoryRoot, map[string]any{"block_number": r, "account_proof": b64Nodes(t, f.AccountProof)}); msg != "" {
				t.Fatalf("attestHistoryRoot: %s", msg)
			}
			if got := hex.EncodeToString([]byte(stateOr(KeyHistoryRootPrefix+strconv.FormatUint(r, 10), ""))); got != bare(f.StorageHash) {
				t.Fatalf("hr-%d = %s, want the account's storage hash %s", r, got, f.StorageHash)
			}
			for _, h := range f.Headers {
				if msg := call(attestHeaders, map[string]any{"root_block": r, "headers": []any{attestItem(t, h.RLP, h.StorageProof)}}); msg != "" {
					t.Fatalf("attest block %d (root-%d): %s", h.Number, r-h.Number, msg)
				}
				p := parseHeader(bare(h.RLP))
				want := []byte{HeaderVersionV1}
				want = appendUint64(want, p.BlockNumber)
				want = append(append(append(want, p.StateRoot[:]...), p.TxRoot[:]...), p.RcptRoot[:]...)
				for _, v := range []uint64{p.BaseFeePerGas, p.GasLimit, p.Timestamp, 11155111} {
					want = appendUint64(want, v)
				}
				if got := stateOr(KeyBlockPrefix+strconv.FormatUint(h.Number, 10), ""); got != string(want) {
					t.Fatalf("b-%d is not the attested header", h.Number)
				}
				if parentOf(h.Number) != hex.EncodeToString(p.ParentHash[:]) {
					t.Fatalf("ph-%d not stored", h.Number)
				}
			}
			if getLastHeight() != r {
				t.Fatalf("attesting moved the tip to %d", getLastHeight())
			}
			// Attesting a stored header again writes nothing: no second log
			// entry, which would prune it early or twice.
			tail := stateUint(KeyStoreLogTail)
			h := f.Headers[1]
			if msg := call(attestHeaders, map[string]any{"root_block": r, "headers": []any{attestItem(t, h.RLP, h.StorageProof)}}); msg != "" {
				t.Fatal(msg)
			}
			if stateUint(KeyStoreLogTail) != tail || tail != 4 {
				t.Fatalf("store log tail %d -> %d after a repeat, want 4 entries (root + 3)", tail, stateUint(KeyStoreLogTail))
			}
		})
	}
}

func TestRP9_AttestRefusesWhatTheProofDoesNotShow(t *testing.T) {
	f := loadFixture(t, "mainnet")
	r := f.RootBlock
	near, far := f.Headers[1], f.Headers[2] // root-100, root-8191
	fresh := func() {
		storeRoot(t, f)
		if msg := call(attestHistoryRoot, map[string]any{"block_number": r, "account_proof": b64Nodes(t, f.AccountProof)}); msg != "" {
			t.Fatal(msg)
		}
	}
	attest := func(root uint64, rlp string, proof []string) string {
		return call(attestHeaders, map[string]any{"root_block": root, "headers": []any{attestItem(t, rlp, proof)}})
	}
	fresh()
	// Another block's storage proof: a different slot, so the key is not shown.
	if msg := attest(r, near.RLP, far.StorageProof); !strings.Contains(msg, "storage_proof of block") {
		t.Errorf("block root-100 with root-8191's proof = %q", msg)
	}
	// A header that is not the block: one byte of its state root changed.
	forged := []byte(bare(near.RLP))
	i := strings.Index(string(forged), hex.EncodeToString(parseHeaderBytes(t, near.RLP)))
	if i < 0 {
		t.Fatal("state root not found in the RLP hex")
	}
	if forged[i] == 'a' {
		forged[i] = 'b'
	} else {
		forged[i] = 'a'
	}
	if msg := attest(r, string(forged), near.StorageProof); !strings.Contains(msg, "does not hash to the block hash") {
		t.Errorf("a forged header = %q", msg)
	}
	// A proof missing a node.
	if msg := attest(r, near.RLP, near.StorageProof[:len(near.StorageProof)-1]); !strings.Contains(msg, "storage_proof of block") {
		t.Errorf("a truncated proof = %q", msg)
	}
	// The window: the slot of block R-8191 holds it only in the states of
	// blocks R-8190 .. R. Plant the same history root under R+1 and R-8191.
	root := stateOr(KeyHistoryRootPrefix+strconv.FormatUint(r, 10), "")
	sdk.StateSetObject(KeyHistoryRootPrefix+strconv.FormatUint(r+1, 10), root)
	if msg := attest(r+1, far.RLP, far.StorageProof); !strings.Contains(msg, "outside the history window") {
		t.Errorf("block R-8191 against root R+1 = %q", msg)
	}
	sdk.StateSetObject(KeyHistoryRootPrefix+strconv.FormatUint(near.Number, 10), root)
	if msg := attest(near.Number, near.RLP, near.StorageProof); !strings.Contains(msg, "outside the history window") {
		t.Errorf("a block against its own root = %q", msg)
	}
	if stored(near.Number) || stored(far.Number) {
		t.Fatal("a refused attestation stored a header")
	}
	// The account proof must be against the stored block's state root.
	fresh()
	other := f.RootBlock - 1
	storeVerifiedHeader(parseHeader(bare(f.Headers[0].RLP)), 11155111, r) // block R-1, another state root
	if msg := call(attestHistoryRoot, map[string]any{"block_number": other, "account_proof": b64Nodes(t, f.AccountProof)}); !strings.Contains(msg, "account_proof") {
		t.Errorf("R's account proof against block R-1's state root = %q", msg)
	}
	if msg := call(attestHistoryRoot, map[string]any{"block_number": r + 5, "account_proof": b64Nodes(t, f.AccountProof)}); !strings.Contains(msg, "is not stored") {
		t.Errorf("an unstored block = %q", msg)
	}
	if msg := call(attestHistoryRoot, map[string]any{"block_number": r, "account_proof": "!!"}); msg != "" {
		t.Errorf("a stored history root is not recomputed, got %q", msg)
	}
}

// parseHeaderBytes returns the state root of a header given as hex.
func parseHeaderBytes(t *testing.T, rlpHex string) []byte {
	t.Helper()
	p := parseHeader(bare(rlpHex))
	return p.StateRoot[:]
}

// oneLeafTrie is the root and the single node of a trie holding only key->value.
func oneLeafTrie(key, value []byte) ([32]byte, []byte) {
	k := keccak(key)
	leaf := rlpList(rlpBytes(append([]byte{0x20}, k[:]...)), rlpBytes(value))
	return keccak(leaf), leaf
}

// TestRP9_SyntheticTries checks the account and value decoding the real proofs
// cannot vary: the code hash, a non-canonical storage value, an absent key.
func TestRP9_SyntheticTries(t *testing.T) {
	head := testChain(500, 1, [32]byte{3}, 0)[0]
	slot := word(head.number % HistoryServeWindow)
	storageRoot, storageLeaf := oneLeafTrie(slot, rlpBytes(head.hash[:]))
	addr, _ := hex.DecodeString(HistoryContractHex)
	code, _ := hex.DecodeString(HistoryCodeHashHex)
	acct := func(codeHash []byte, sroot [32]byte) ([32]byte, []byte) {
		return oneLeafTrie(addr, rlpList(rlpUint(1), rlpUint(0), rlpBytes(sroot[:]), rlpBytes(codeHash)))
	}
	setup := func(stateRoot [32]byte) {
		setupVerifier(t, 8000, [32]byte{1})
		var p parsedHeader
		p.BlockNumber, p.StateRoot = 8000, stateRoot
		storeVerifiedHeader(p, 11155111, 8000)
	}
	b64 := func(nodes ...[]byte) string {
		var all []byte
		for _, n := range nodes {
			all = append(all, n...)
		}
		return base64.StdEncoding.EncodeToString(all)
	}
	attestHead := func(proof string) string {
		return call(attestHeaders, map[string]any{"root_block": 8000, "headers": []any{map[string]string{"rlp_hex": hex.EncodeToString(head.rlp), "storage_proof": proof}}})
	}

	// The history contract with the right code: the header is attested.
	sr, leaf := acct(code, storageRoot)
	setup(sr)
	if msg := call(attestHistoryRoot, map[string]any{"block_number": 8000, "account_proof": b64(leaf)}); msg != "" {
		t.Fatal(msg)
	}
	if msg := attestHead(b64(storageLeaf)); msg != "" || !stored(500) {
		t.Fatalf("a synthetic one-leaf attestation: %q", msg)
	}

	// Any other code at that address: refused.
	wrong := append([]byte{}, code...)
	wrong[0] ^= 1
	sr, leaf = acct(wrong, storageRoot)
	setup(sr)
	if msg := call(attestHistoryRoot, map[string]any{"block_number": 8000, "account_proof": b64(leaf)}); !strings.Contains(msg, "not the EIP-2935 history contract") {
		t.Errorf("another contract's code = %q", msg)
	}
	// The right code but a storage root that is not 32 bytes: refused, nothing stored.
	sr, leaf = oneLeafTrie(addr, rlpList(rlpUint(1), rlpUint(0), rlpBytes(storageRoot[:31]), rlpBytes(code)))
	setup(sr)
	if msg := call(attestHistoryRoot, map[string]any{"block_number": 8000, "account_proof": b64(leaf)}); !strings.Contains(msg, "the account is not [nonce, balance, storageRoot, codeHash]") {
		t.Errorf("a 31-byte storage root = %q", msg)
	}
	if msg := attestHead(b64(storageLeaf)); !strings.Contains(msg, "no history root") {
		t.Errorf("after a refused account: %q, want no history root stored", msg)
	}
	// Another account's proof (the key differs): absent.
	sr, leaf = oneLeafTrie([]byte("not the history contract!!"), rlpList(rlpUint(1), rlpUint(0), rlpBytes(storageRoot[:]), rlpBytes(code)))
	setup(sr)
	if msg := call(attestHistoryRoot, map[string]any{"block_number": 8000, "account_proof": b64(leaf)}); !strings.Contains(msg, "not in the trie") {
		t.Errorf("another account's proof = %q", msg)
	}

	// Storage values: a leading zero byte is non-canonical, a list is not a word.
	for name, v := range map[string][]byte{
		"leading zero": rlpBytes(append([]byte{0}, head.hash[:31]...)),
		"list":         rlpList(rlpBytes(head.hash[:])),
		"too long":     rlpBytes(append(head.hash[:], 1)),
	} {
		sroot, sleaf := oneLeafTrie(slot, v)
		sr, leaf = acct(code, sroot)
		setup(sr)
		if msg := call(attestHistoryRoot, map[string]any{"block_number": 8000, "account_proof": b64(leaf)}); msg != "" {
			t.Fatal(msg)
		}
		if msg := attestHead(b64(sleaf)); !strings.Contains(msg, "does not hash") {
			t.Errorf("storage value %s = %q", name, msg)
		}
	}
	// A proof with too many nodes is refused before any work.
	many := make([][]byte, MaxProofNodes+1)
	for i := range many {
		many[i] = storageLeaf
	}
	sr, leaf = acct(code, storageRoot)
	setup(sr)
	call(attestHistoryRoot, map[string]any{"block_number": 8000, "account_proof": b64(leaf)})
	if msg := attestHead(b64(many...)); !strings.Contains(msg, "more than") {
		t.Errorf("21 nodes = %q", msg)
	}
}

// RP-6: a header lives max_retention blocks of the proven tip from when it was
// stored, whatever its height, then is pruned with its parent hash and history
// root. Old code pruned by height: header N-mr when header N was stored.
func TestRP6_HeadersLiveRetentionFromWhenStored(t *testing.T) {
	setupVerifier(t, 10_000, [32]byte{1})
	sdk.StateSetObject(KeyMaxRetention, "7200")
	prove := func(n uint64) {
		t.Helper()
		if msg := call(submitProof, proveTip(testChain(n, 1, [32]byte{byte(n)}, 0))); msg != "" {
			t.Fatalf("proof at %d: %s", n, msg)
		}
	}
	prove(10_001)
	sdk.StateSetObject(KeyHistoryRootPrefix+"10001", strings.Repeat("r", 32))
	// A header far below the tip, stored now (a late recovery), at tip 10,001.
	old := testChain(2_000, 2, [32]byte{5}, 0)
	sdk.StateSetObject(KeyParentPrefix+"2002", string(old[1].hash[:]))
	if msg := call(submitHeaders, map[string]any{"headers": headersJSON(old)}); msg != "" {
		t.Fatal(msg)
	}
	prove(17_201) // 7,200 after: everything still kept
	if !stored(10_001) || !stored(2_000) || !stored(2_001) {
		t.Fatalf("pruned at exactly max_retention: b-10001 %v b-2000 %v", stored(10_001), stored(2_000))
	}
	prove(17_202) // one more: the entries stored at 10,001 expire, two per store
	if stored(10_001) || parentOf(10_001) != "" || sdk.StateGetObject(KeyHistoryRootPrefix+"10001") != nil {
		t.Fatal("b-10001 (or its ph-/hr-) not pruned past max_retention")
	}
	if !stored(17_201) {
		t.Fatal("a fresh header was pruned")
	}
	prove(17_203)
	if stored(2_000) || stored(2_001) {
		t.Fatal("headers stored at tip 10,001 not pruned by tip 17,203")
	}
	if head, tail := stateUint(KeyStoreLogHead), stateUint(KeyStoreLogTail); head != 3 || tail != 6 {
		t.Fatalf("store log head %d tail %d, want 3 and 6", head, tail)
	}
}

func TestRP6_HugeRetentionKeepsEverything(t *testing.T) {
	setupVerifier(t, 10_000, [32]byte{1})
	sdk.StateSetObject(KeyMaxRetention, "18446744073709551615")
	for _, n := range []uint64{10_001, 900_000, 90_000_000} {
		if msg := call(submitProof, proveTip(testChain(n, 1, [32]byte{2}, 0))); msg != "" {
			t.Fatal(msg)
		}
	}
	if !stored(10_001) || !stored(900_000) {
		t.Fatal("a near-2^64 retention pruned")
	}
}
