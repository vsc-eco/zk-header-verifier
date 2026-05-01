package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	ce "zk-header-verifier/contract/contracterrors"
	"zk-header-verifier/sdk"
)

func main() {}

const (
	KeyLastHeight  = "h"
	KeyBlockPrefix = "b-"
	KeyGroth16Vk   = "vk"
	KeyVkRoot      = "vr"
	KeySp1VkeyHash = "sp1vk"
	KeyMaxRetention = "mr"
	DefaultMaxRetention = uint64(10000)

	// Max headers per transaction. Limited by Magi's 16KB MAX_TX_SIZE.
	// Each header with RLP hex costs ~681 CBOR bytes. 12 × 681 + 1000 overhead = ~9172 bytes.
	MaxHeadersPerTx = 12

	// ProofOutputs ABI layout (alloy::abi_encode of the SP1 program's output struct).
	// alloy emits a 32-byte tuple head offset (always 0x20), then 8 head fields of
	// 32 bytes each, then the dynamic tail. This contract reads fields 5/6/7 only.
	// Offsets are computed from a fixed PvAbiOffset = 32; we assert the runtime
	// value equals that constant before indexing, so int conversion is unnecessary.
	PvAbiOffset        = 32                 // alloy tuple head, asserted equal at runtime
	PvFieldStateRoot   = PvAbiOffset + 5*32 // 192
	PvFieldBlockHash   = PvAbiOffset + 6*32 // 224
	PvFieldBlockNumber = PvAbiOffset + 7*32 // 256
	PvMinLen           = PvAbiOffset + 8*32 // 288 — 8 head fields fully present
)

// --- Admin actions ---

//go:wasmexport init
func initContract(input *string) *string {
	checkOwner()
	var params struct {
		Groth16Vk   string `json:"groth16_vk"`
		VkRoot      string `json:"vk_root"`
		Sp1VkeyHash string `json:"sp1_vkey_hash"`
	}
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON", "init")
	}
	if params.Groth16Vk == "" || params.VkRoot == "" || params.Sp1VkeyHash == "" {
		ce.Abort(ce.ErrInput, "groth16_vk, vk_root, and sp1_vkey_hash required", "init")
	}
	sdk.StateSetObject(KeyGroth16Vk, params.Groth16Vk)
	sdk.StateSetObject(KeyVkRoot, params.VkRoot)
	sdk.StateSetObject(KeySp1VkeyHash, params.Sp1VkeyHash)
	sdk.StateSetObject(KeyMaxRetention, strconv.FormatUint(DefaultMaxRetention, 10))
	return nil
}

//go:wasmexport updateVkey
func updateVkey(input *string) *string {
	checkOwner()
	var params struct {
		Groth16Vk   string `json:"groth16_vk"`
		VkRoot      string `json:"vk_root"`
		Sp1VkeyHash string `json:"sp1_vkey_hash"`
	}
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON", "updateVkey")
	}
	if params.Groth16Vk != "" {
		sdk.StateSetObject(KeyGroth16Vk, params.Groth16Vk)
	}
	if params.VkRoot != "" {
		sdk.StateSetObject(KeyVkRoot, params.VkRoot)
	}
	if params.Sp1VkeyHash != "" {
		sdk.StateSetObject(KeySp1VkeyHash, params.Sp1VkeyHash)
	}
	return nil
}

// --- Permissionless proof submission ---

type SubmitProofParams struct {
	Proof        string            `json:"proof"`
	PublicValues string            `json:"public_values"`
	Headers      []SubmittedHeader `json:"headers"`
}

// SubmittedHeader carries only the canonical RLP. All header fields are
// extracted from the RLP itself; JSON copies are not trusted.
type SubmittedHeader struct {
	RlpHex string `json:"rlp_hex"`
}

//go:wasmexport submitProof
func submitProof(input *string) *string {
	var params SubmitProofParams
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON: "+err.Error(), "submitProof")
	}
	if params.Proof == "" || params.PublicValues == "" || len(params.Headers) == 0 {
		ce.Abort(ce.ErrInput, "proof, public_values, and headers required", "submitProof")
	}
	if len(params.Headers) > MaxHeadersPerTx {
		ce.Abort(ce.ErrInput, "too many headers (max "+strconv.Itoa(MaxHeadersPerTx)+")", "submitProof")
	}

	// Load verification parameters
	groth16Vk := sdk.StateGetObject(KeyGroth16Vk)
	if groth16Vk == nil || *groth16Vk == "" {
		ce.Abort(ce.ErrInitialization, "not initialized: no groth16_vk", "submitProof")
	}
	vkRoot := sdk.StateGetObject(KeyVkRoot)
	if vkRoot == nil || *vkRoot == "" {
		ce.Abort(ce.ErrInitialization, "not initialized: no vk_root", "submitProof")
	}
	sp1VkeyHash := sdk.StateGetObject(KeySp1VkeyHash)
	if sp1VkeyHash == nil || *sp1VkeyHash == "" {
		ce.Abort(ce.ErrInitialization, "not initialized: no sp1_vkey_hash", "submitProof")
	}

	// 1. Verify the ZK proof
	result := sdk.Sp1VerifyGroth16(params.Proof, params.PublicValues, *sp1VkeyHash, *groth16Vk, *vkRoot)
	if result != "true" {
		ce.Abort(ce.ErrTransaction, "proof verification failed", "submitProof")
	}

	// 2. Decode publicValues to get proven block hash and number
	pvBytes, err := hex.DecodeString(params.PublicValues)
	if err != nil {
		ce.Abort(ce.ErrInvalidHex, "invalid public_values hex", "submitProof")
	}
	provenStateRoot, provenBlockHash, provenBlockNumber, perr := parseProvenFields(pvBytes)
	if perr != nil {
		ce.CustomAbort(ce.Prepend(perr, "submitProof"))
	}

	// 3. Parse every header from its RLP and compute keccak hashes.
	// Trust flows: proof -> provenBlockHash -> last RLP keccak -> earlier RLPs
	// via parentHash chain -> all extracted fields from each RLP.
	lastIdx := len(params.Headers) - 1
	parsed := make([]parsedHeader, len(params.Headers))
	hashes := make([]string, len(params.Headers))
	for i, h := range params.Headers {
		parsed[i] = parseHeader(h.RlpHex)
		hashes[i] = sdk.Keccak256(h.RlpHex)
	}

	// 4. Bind the last header's RLP and extracted fields to the proof's public inputs.
	if hashes[lastIdx] != provenBlockHash {
		ce.Abort(ce.ErrTransaction, "keccak256(last header RLP) != proven block hash", "submitProof")
	}
	if parsed[lastIdx].BlockNumber != provenBlockNumber {
		ce.Abort(ce.ErrTransaction, "last header block number ("+
			strconv.FormatUint(parsed[lastIdx].BlockNumber, 10)+
			") != proven block number ("+
			strconv.FormatUint(provenBlockNumber, 10)+")", "submitProof")
	}
	if hex.EncodeToString(parsed[lastIdx].StateRoot[:]) != provenStateRoot {
		ce.Abort(ce.ErrTransaction, "last header state_root != proven state root", "submitProof")
	}

	// 5. Walk the keccak chain backward. parentHash comes from the parsed RLP,
	// so if this passes, every earlier header's RLP is bound to a real ancestor.
	for i := lastIdx - 1; i >= 0; i-- {
		expectedParent := hex.EncodeToString(parsed[i+1].ParentHash[:])
		if expectedParent != hashes[i] {
			ce.Abort(ce.ErrTransaction, "hash chain broken at block "+
				strconv.FormatUint(parsed[i].BlockNumber, 10), "submitProof")
		}
	}

	// 6. Sequential block-number check + store the RLP-extracted fields.
	lastHeight := getLastHeight()
	maxRetention := getMaxRetention()
	for i := range parsed {
		p := parsed[i]
		if lastHeight > 0 && p.BlockNumber != lastHeight+1 {
			ce.Abort(ce.ErrInput, "block heights must be sequential", "submitProof")
		}
		if i > 0 && p.BlockNumber != parsed[i-1].BlockNumber+1 {
			ce.Abort(ce.ErrInput, "headers not sequential within batch", "submitProof")
		}

		storeHeader(p.BlockNumber, p.StateRoot, p.TxRoot, p.RcptRoot, p.BaseFeePerGas, p.GasLimit, p.Timestamp)
		lastHeight = p.BlockNumber

		if p.BlockNumber > maxRetention {
			sdk.StateDeleteObject(KeyBlockPrefix + strconv.FormatUint(p.BlockNumber-maxRetention, 10))
		}
	}

	sdk.StateSetObject(KeyLastHeight, strconv.FormatUint(lastHeight, 10))
	return nil
}

// --- RLP decoder ---
//
// Header field order (post-merge Ethereum, per yellow paper / EIP-1559):
//   0  parentHash         9  gasLimit
//   1  ommersHash         10 gasUsed
//   2  coinbase           11 timestamp
//   3  stateRoot          12 extraData
//   4  transactionsRoot   13 mixHash
//   5  receiptsRoot       14 nonce
//   6  logsBloom          15 baseFeePerGas
//   7  difficulty         (16+ withdrawalsRoot/blob fields ignored)
//   8  number

type parsedHeader struct {
	BlockNumber   uint64
	ParentHash    [32]byte
	StateRoot     [32]byte
	TxRoot        [32]byte
	RcptRoot      [32]byte
	GasLimit      uint64
	Timestamp     uint64
	BaseFeePerGas uint64
}

func parseHeader(rlpHex string) parsedHeader {
	rlpBytes, err := hex.DecodeString(rlpHex)
	if err != nil {
		ce.Abort(ce.ErrInvalidHex, "invalid rlp_hex", "submitProof")
	}
	payloadStart, _, _, isList := readRLPItem(rlpBytes, 0)
	if !isList {
		ce.Abort(ce.ErrInput, "rlp not a list", "submitProof")
	}
	p := payloadStart
	var h parsedHeader

	p = readBytes32(rlpBytes, p, &h.ParentHash)
	p = skipItem(rlpBytes, p) // ommersHash
	p = skipItem(rlpBytes, p) // coinbase
	p = readBytes32(rlpBytes, p, &h.StateRoot)
	p = readBytes32(rlpBytes, p, &h.TxRoot)
	p = readBytes32(rlpBytes, p, &h.RcptRoot)
	p = skipItem(rlpBytes, p) // logsBloom
	p = skipItem(rlpBytes, p) // difficulty
	p, h.BlockNumber = readUintField(rlpBytes, p)
	p, h.GasLimit = readUintField(rlpBytes, p)
	p = skipItem(rlpBytes, p) // gasUsed
	p, h.Timestamp = readUintField(rlpBytes, p)
	p = skipItem(rlpBytes, p) // extraData
	p = skipItem(rlpBytes, p) // mixHash
	p = skipItem(rlpBytes, p) // nonce
	_, h.BaseFeePerGas = readUintField(rlpBytes, p)

	return h
}

// readRLPItem returns (valueStart, valueLen, nextOffset, isList) for the RLP
// item beginning at buf[offset]. Reverts on truncated/malformed input.
func readRLPItem(buf []byte, offset int) (int, int, int, bool) {
	if offset >= len(buf) {
		ce.Abort(ce.ErrInput, "rlp truncated", "submitProof")
	}
	b := buf[offset]
	switch {
	case b < 0x80:
		// single byte 0x00..0x7f is its own encoding
		return offset, 1, offset + 1, false
	case b < 0xb8:
		l := int(b - 0x80)
		if offset+1+l > len(buf) {
			ce.Abort(ce.ErrInput, "rlp string truncated", "submitProof")
		}
		return offset + 1, l, offset + 1 + l, false
	case b < 0xc0:
		ll := int(b - 0xb7)
		if offset+1+ll > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-string len truncated", "submitProof")
		}
		l := readRLPLen(buf[offset+1 : offset+1+ll])
		end := offset + 1 + ll + l
		if end > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-string truncated", "submitProof")
		}
		return offset + 1 + ll, l, end, false
	case b < 0xf8:
		l := int(b - 0xc0)
		if offset+1+l > len(buf) {
			ce.Abort(ce.ErrInput, "rlp short-list truncated", "submitProof")
		}
		return offset + 1, l, offset + 1 + l, true
	default:
		ll := int(b - 0xf7)
		if offset+1+ll > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-list len truncated", "submitProof")
		}
		l := readRLPLen(buf[offset+1 : offset+1+ll])
		end := offset + 1 + ll + l
		if end > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-list truncated", "submitProof")
		}
		return offset + 1 + ll, l, end, true
	}
}

func readRLPLen(buf []byte) int {
	if len(buf) > 8 {
		ce.Abort(ce.ErrInput, "rlp len overflow", "submitProof")
	}
	var v int
	for _, b := range buf {
		v = (v << 8) | int(b)
	}
	return v
}

func readBytes32(buf []byte, offset int, out *[32]byte) int {
	s, l, next, isList := readRLPItem(buf, offset)
	if isList {
		ce.Abort(ce.ErrInput, "rlp expected string, got list", "submitProof")
	}
	if l != 32 {
		ce.Abort(ce.ErrInput, "rlp expected 32-byte field", "submitProof")
	}
	copy(out[:], buf[s:s+32])
	return next
}

func skipItem(buf []byte, offset int) int {
	_, _, next, _ := readRLPItem(buf, offset)
	return next
}

func readUintField(buf []byte, offset int) (int, uint64) {
	s, l, next, isList := readRLPItem(buf, offset)
	if isList {
		ce.Abort(ce.ErrInput, "rlp expected uint, got list", "submitProof")
	}
	if l > 8 {
		ce.Abort(ce.ErrInput, "rlp uint > 8 bytes", "submitProof")
	}
	var v uint64
	for i := 0; i < l; i++ {
		v = (v << 8) | uint64(buf[s+i])
	}
	return next, v
}

// --- Storage helpers ---

func storeHeader(blockNumber uint64, stateRoot, txRoot, rcptRoot [32]byte, baseFee, gasLimit, timestamp uint64) {
	buf := make([]byte, 0, 128)
	buf = appendUint64(buf, blockNumber)
	buf = append(buf, stateRoot[:]...)
	buf = append(buf, txRoot[:]...)
	buf = append(buf, rcptRoot[:]...)
	buf = appendUint64(buf, baseFee)
	buf = appendUint64(buf, gasLimit)
	buf = appendUint64(buf, timestamp)
	sdk.StateSetObject(KeyBlockPrefix+strconv.FormatUint(blockNumber, 10), string(buf))
}

func getLastHeight() uint64 {
	data := sdk.StateGetObject(KeyLastHeight)
	if data == nil || *data == "" {
		return 0
	}
	h, _ := strconv.ParseUint(*data, 10, 64)
	return h
}

func getMaxRetention() uint64 {
	data := sdk.StateGetObject(KeyMaxRetention)
	if data == nil || *data == "" {
		return DefaultMaxRetention
	}
	v, _ := strconv.ParseUint(*data, 10, 64)
	return v
}

func checkOwner() {
	caller := sdk.GetEnv().Caller.String()
	owner := sdk.GetEnvKey("contract.owner")
	if owner == nil || caller != *owner {
		ce.Abort(ce.ErrNoPermission, "owner required", "auth")
	}
}

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func readUint64BE(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

// parseProvenFields extracts (executionStateRoot, executionBlockHash, executionBlockNumber)
// from the SP1 program's ABI-encoded ProofOutputs bytes. Returns a non-nil *ContractError
// on any structural problem. No SDK calls — pure function, safe to test under standard
// go test (contracterrors transitively imports sdk but its construction path doesn't
// exercise any wasmimport).
func parseProvenFields(pvBytes []byte) (stateRoot, blockHash string, blockNumber uint64, err *ce.ContractError) {
	if len(pvBytes) < PvMinLen {
		return "", "", 0, ce.NewContractError(ce.ErrInput, "public_values too short for ABI fields")
	}
	if readUint64BE(pvBytes[24:32]) != PvAbiOffset {
		return "", "", 0, ce.NewContractError(ce.ErrInput, "unexpected ABI tuple offset (expected 32)")
	}
	stateRoot = hex.EncodeToString(pvBytes[PvFieldStateRoot : PvFieldStateRoot+32])
	blockHash = hex.EncodeToString(pvBytes[PvFieldBlockHash : PvFieldBlockHash+32])
	blockNumber = readUint64BE(pvBytes[PvFieldBlockNumber+24 : PvFieldBlockNumber+32])
	return
}
