package main

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
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

	// ABI offsets into the modified ProofOutputs struct (all fields are 32 bytes)
	// executionBlockHash is at field index 6 (after prevHeader, prevHead,
	// prevSyncCommitteeHash, newHead, newHeader, executionStateRoot)
	OffsetBlockHash   = 192 // 6 * 32
	OffsetBlockNumber = 224 // 7 * 32
	MinPublicValuesLen = 256 // need at least 8 fields
)

// --- Admin actions ---

//go:wasmexport init
func initContract() {
	checkOwner()
	payload := sdk.GetEnvKey("msg.payload")
	if payload == nil {
		sdk.Revert("no payload", "init")
	}
	var params struct {
		Groth16Vk   string `json:"groth16_vk"`
		VkRoot      string `json:"vk_root"`
		Sp1VkeyHash string `json:"sp1_vkey_hash"`
	}
	if err := json.Unmarshal([]byte(*payload), &params); err != nil {
		sdk.Revert("invalid JSON", "init")
	}
	if params.Groth16Vk == "" || params.VkRoot == "" || params.Sp1VkeyHash == "" {
		sdk.Revert("groth16_vk, vk_root, and sp1_vkey_hash required", "init")
	}
	sdk.StateSetObject(KeyGroth16Vk, params.Groth16Vk)
	sdk.StateSetObject(KeyVkRoot, params.VkRoot)
	sdk.StateSetObject(KeySp1VkeyHash, params.Sp1VkeyHash)
	sdk.StateSetObject(KeyMaxRetention, strconv.FormatUint(DefaultMaxRetention, 10))
}

//go:wasmexport updateVkey
func updateVkey() {
	checkOwner()
	payload := sdk.GetEnvKey("msg.payload")
	if payload == nil {
		sdk.Revert("no payload", "updateVkey")
	}
	var params struct {
		Groth16Vk   string `json:"groth16_vk"`
		VkRoot      string `json:"vk_root"`
		Sp1VkeyHash string `json:"sp1_vkey_hash"`
	}
	if err := json.Unmarshal([]byte(*payload), &params); err != nil {
		sdk.Revert("invalid JSON", "updateVkey")
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
}

// --- Permissionless proof submission ---

type SubmitProofParams struct {
	Proof        string            `json:"proof"`
	PublicValues string            `json:"public_values"`
	Headers      []SubmittedHeader `json:"headers"`
}

type SubmittedHeader struct {
	RlpHex           string `json:"rlp_hex"`
	BlockNumber      uint64 `json:"block_number"`
	TransactionsRoot string `json:"transactions_root"`
	ReceiptsRoot     string `json:"receipts_root"`
	BaseFeePerGas    uint64 `json:"base_fee_per_gas"`
	GasLimit         uint64 `json:"gas_limit"`
	Timestamp        uint64 `json:"timestamp"`
}

//go:wasmexport submitProof
func submitProof() {
	payload := sdk.GetEnvKey("msg.payload")
	if payload == nil {
		sdk.Revert("no payload", "submitProof")
	}
	var params SubmitProofParams
	if err := json.Unmarshal([]byte(*payload), &params); err != nil {
		sdk.Revert("invalid JSON: "+err.Error(), "submitProof")
	}
	if params.Proof == "" || params.PublicValues == "" || len(params.Headers) == 0 {
		sdk.Revert("proof, public_values, and headers required", "submitProof")
	}
	if len(params.Headers) > MaxHeadersPerTx {
		sdk.Revert("too many headers (max "+strconv.Itoa(MaxHeadersPerTx)+")", "submitProof")
	}

	// Load verification parameters
	groth16Vk := sdk.StateGetObject(KeyGroth16Vk)
	if groth16Vk == nil || *groth16Vk == "" {
		sdk.Revert("not initialized: no groth16_vk", "submitProof")
	}
	vkRoot := sdk.StateGetObject(KeyVkRoot)
	if vkRoot == nil || *vkRoot == "" {
		sdk.Revert("not initialized: no vk_root", "submitProof")
	}
	sp1VkeyHash := sdk.StateGetObject(KeySp1VkeyHash)
	if sp1VkeyHash == nil || *sp1VkeyHash == "" {
		sdk.Revert("not initialized: no sp1_vkey_hash", "submitProof")
	}

	// 1. Verify the ZK proof
	result := sdk.Sp1VerifyGroth16(params.Proof, params.PublicValues, *sp1VkeyHash, *groth16Vk, *vkRoot)
	if result != "true" {
		sdk.Revert("proof verification failed", "submitProof")
	}

	// 2. Decode publicValues to get proven block hash and number
	pvBytes, err := hex.DecodeString(params.PublicValues)
	if err != nil || len(pvBytes) < MinPublicValuesLen {
		sdk.Revert("public_values too short or invalid hex", "submitProof")
	}
	provenBlockHash := hex.EncodeToString(pvBytes[OffsetBlockHash : OffsetBlockHash+32])
	provenBlockNumber := readUint64BE(pvBytes[OffsetBlockNumber+24:]) // last 8 bytes of uint256

	// 3. Verify hash chain: last header must match proven block hash
	lastIdx := len(params.Headers) - 1
	lastHeader := params.Headers[lastIdx]

	if lastHeader.BlockNumber != provenBlockNumber {
		sdk.Revert("last header block number ("+
			strconv.FormatUint(lastHeader.BlockNumber, 10)+
			") != proven block number ("+
			strconv.FormatUint(provenBlockNumber, 10)+")", "submitProof")
	}

	lastHeaderHash := sdk.Keccak256(lastHeader.RlpHex)
	if lastHeaderHash != provenBlockHash {
		sdk.Revert("keccak256(last header RLP) != proven block hash", "submitProof")
	}

	// 4. Verify hash chain backwards: each header's parentHash == hash of previous
	headerHashes := make([]string, len(params.Headers))
	headerHashes[lastIdx] = lastHeaderHash

	for i := lastIdx - 1; i >= 0; i-- {
		headerHashes[i] = sdk.Keccak256(params.Headers[i].RlpHex)

		// parentHash is the first 32 bytes of the RLP-decoded header.
		// In RLP encoding: list prefix (variable 1-3 bytes) + parentHash (32 bytes).
		// We extract parentHash from the NEXT header's RLP to verify the chain.
		nextParentHash := extractParentHash(params.Headers[i+1].RlpHex)
		if nextParentHash != headerHashes[i] {
			sdk.Revert("hash chain broken at block "+
				strconv.FormatUint(params.Headers[i].BlockNumber, 10), "submitProof")
		}
	}

	// 5. Check sequential and store
	lastHeight := getLastHeight()
	for i, header := range params.Headers {
		if lastHeight > 0 && header.BlockNumber != lastHeight+1 {
			sdk.Revert("block heights must be sequential", "submitProof")
		}
		if i > 0 && header.BlockNumber != params.Headers[i-1].BlockNumber+1 {
			sdk.Revert("headers not sequential within batch", "submitProof")
		}

		txRoot, err := hexTo32(header.TransactionsRoot)
		if err != nil {
			sdk.Revert("invalid transactions_root", "submitProof")
		}
		rcptRoot, err := hexTo32(header.ReceiptsRoot)
		if err != nil {
			sdk.Revert("invalid receipts_root", "submitProof")
		}

		storeHeader(header.BlockNumber, txRoot, rcptRoot, header.BaseFeePerGas, header.GasLimit, header.Timestamp)
		lastHeight = header.BlockNumber

		maxRetention := getMaxRetention()
		if header.BlockNumber > maxRetention {
			sdk.StateDeleteObject(KeyBlockPrefix + strconv.FormatUint(header.BlockNumber-maxRetention, 10))
		}
	}

	sdk.StateSetObject(KeyLastHeight, strconv.FormatUint(lastHeight, 10))
}

// extractParentHash reads the parentHash from an RLP-encoded block header.
// The RLP structure is: rlp_list_prefix + parentHash(32 bytes) + ...
// For post-merge Ethereum headers, the list prefix is 3 bytes (0xf9 + 2-byte length).
// parentHash is always the first element, starting at byte 3.
func extractParentHash(rlpHex string) string {
	// Decode enough bytes to get the list prefix + parentHash
	if len(rlpHex) < 70 { // 3 bytes prefix + 32 bytes parentHash = 35 bytes = 70 hex chars
		return ""
	}
	rlpBytes, err := hex.DecodeString(rlpHex[:70])
	if err != nil {
		return ""
	}

	// Determine RLP list prefix length
	firstByte := rlpBytes[0]
	var dataStart int
	if firstByte >= 0xf8 {
		// Long list: 1 byte type + N bytes length
		lenBytes := int(firstByte - 0xf7)
		dataStart = 1 + lenBytes
	} else if firstByte >= 0xc0 {
		// Short list: 1 byte
		dataStart = 1
	} else {
		return ""
	}

	if len(rlpBytes) < dataStart+32 {
		return ""
	}
	return hex.EncodeToString(rlpBytes[dataStart : dataStart+32])
}

// --- Storage helpers ---

func storeHeader(blockNumber uint64, txRoot, rcptRoot [32]byte, baseFee, gasLimit, timestamp uint64) {
	buf := make([]byte, 0, 96)
	buf = appendUint64(buf, blockNumber)
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
		sdk.Revert("owner required", "auth")
	}
}

func hexTo32(s string) ([32]byte, error) {
	var result [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return result, err
	}
	copy(result[:], b)
	return result, nil
}

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func readUint64BE(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}
