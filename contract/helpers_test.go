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

// Test helpers: RLP, synthetic header chains, ABI public values and handler calls.

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

func setupVerifier(t *testing.T, lastHeight uint64, anchor [32]byte) {
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
