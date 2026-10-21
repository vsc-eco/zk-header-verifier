package main

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	ce "zk-header-verifier/contract/contracterrors"
	"zk-header-verifier/sdk"
)

func main() {}

const (
	KeyLastHeight   = "h"
	KeyBlockPrefix  = "b-"
	KeyGroth16Vk    = "vk"
	KeyVkRoot       = "vr"
	KeySp1VkeyHash  = "sp1vk"
	KeyMaxRetention = "mr"

	// W4 Cluster B CRIT #25 — cross-batch parent anchor.
	// On every successful submitProof, KeyLastBlockHash is updated to the
	// last (highest-numbered) block hash in the batch. The next batch must
	// satisfy `parsed[0].ParentHash == lastBlockHash` at the top of
	// submitProof, preventing a forged "first proof" from injecting an
	// arbitrary state. Seeded by `initContract` via the new
	// `initial_block_hash` parameter (atomic backfill at deploy time).
	KeyLastBlockHash = "lbh"

	// W4 Cluster B HIGH #22 — ELF hash pinning.
	// SHA-256 of the SP1 ELF binary the prover is expected to use. The
	// prover startup check reads this and fatal-exits on mismatch. Set
	// via `setExpectedElfHash` admin handler (Fund-affecting class,
	// 400K-block timelock — owned by Cluster B per v18 §AI).
	KeyExpectedElfHash = "elfhash"

	// The chainId LABEL this verifier instance is bound to. Set at init from
	// InitContractParams.ExpectedChainId. This is NOT a security check against
	// the proof (the proof's committed chainId was spoofable); chain identity is
	// established by genesis_root + sync-committee anchoring below. submitProof
	// stamps this configured value into every stored header (bytes 129-136) so
	// account-mapping's per-chain receipt checks (header.ChainId == its chainId)
	// keep working. Required (non-zero) at init.
	KeyExpectedChainId = "cid"

	// Beacon light-client chain binding (genesis pin + sync-committee anchoring).
	// KeyGenesisRoot: the genesis_validators_root this verifier is bound to
	// (bare hex, immutable after init). Every proof must commit this same root.
	// KeyBeaconHead: the last finalized beacon slot accepted (uint64 decimal);
	// submitProof requires strictly increasing newHead (anti-replay/rollback).
	// SyncCommitteePrefix+{period}: the trusted sync-committee hash for each
	// period. A proof is accepted only if its prevSyncCommitteeHash equals the
	// trusted committee for period(prevHead); the proof's committee hashes are
	// then rotated in. Bootstrapped at init from a weak-subjectivity checkpoint.
	KeyGenesisRoot      = "gvr"
	KeyBeaconHead       = "bh"
	SyncCommitteePrefix = "sc-"

	// E5: an open header gap (see submitHeaders). A proof's batch carries at
	// most MaxHeadersPerTx headers, but ~32 blocks lie between finalized
	// checkpoints, so a batch need not reach the stored chain. It is then
	// stored and the blocks below it are backfilled: KeyGapWant is the bare hex
	// hash the next (older) header must have, KeyGapLow the lowest height
	// stored so far, KeyGapBase / KeyGapAnchor the stored chain's tip height and
	// bare hex hash the backfill must meet.
	KeyGapWant   = "gapw"
	KeyGapLow    = "gapl"
	KeyGapBase   = "gapb"
	KeyGapAnchor = "gapa"

	// B13: the bridge proves a deposit or a mined withdrawal against the
	// header of its own block, so a header pruned before that proof lands
	// strands it: past retention a deposit can never be credited and the
	// in-flight withdrawal can never be confirmed or proven dropped. 10,000 ETH
	// blocks was ~33 h, shorter than a bridge-bot outage can last. The default
	// is 7 days (the BTC bridge keeps ~7.5) and init refuses less than a day.
	DefaultMaxRetention = uint64(50_400)
	MinMaxRetention     = uint64(7_200)

	// Max headers per transaction. Limited by Magi's 16KB MAX_TX_SIZE.
	// Each header with RLP hex costs ~681 CBOR bytes. 12 × 681 + 1000 overhead = ~9172 bytes.
	MaxHeadersPerTx = 12

	// MED #65 (A1-F4): cap any RLP length descriptor. A single block header is
	// bounded by Magi's 16KB MAX_TX_SIZE, so no legitimate length descriptor can
	// approach this. The cap is well below 2^31 so a value narrowed to `int`
	// (TinyGo's wasm-unknown target compiles `int` as 32-bit) is always a
	// non-negative number — readRLPItem's `end := offset + 1 + ll + l` can never
	// wrap negative and the downstream slices can never take a negative index.
	MaxRLPItemLen = 1 << 24 // 16 MiB

	// ProofOutputs ABI layout (alloy::abi_encode of the SP1 program's output
	// struct; see sp1-helios-magi/primitives/src/types.rs). The 32-byte tuple
	// offset prefix occupies bytes [0:32]; tuple field N is at PvAbiOffset+N*32.
	// Head fields (all read here except where noted):
	//   slot 1 prevHead (uint256 beacon slot)   slot 2 prevSyncCommitteeHash
	//   slot 3 newHead  (uint256 beacon slot)    slot 5 executionStateRoot
	//   slot 6 executionBlockHash                slot 7 executionBlockNumber
	//   slot 8 syncCommitteeHash                 slot 9 nextSyncCommitteeHash
	//   slot 10 genesisRoot                      slot 11 storageSlots ptr (unread)
	// uint256 beacon slots are read as uint64 from the low 8 bytes ([+24:+32]).
	// PvMinLen=384 guarantees every field through genesisRoot ([352:384]) is
	// present (a well-formed empty-storageSlots proof is 448 bytes).
	PvAbiOffset              = 32                  // alloy tuple head, asserted equal at runtime
	PvFieldPrevHead          = PvAbiOffset + 1*32  // 64
	PvFieldPrevSyncCommittee = PvAbiOffset + 2*32  // 96
	PvFieldNewHead           = PvAbiOffset + 3*32  // 128
	PvFieldStateRoot         = PvAbiOffset + 5*32  // 192
	PvFieldBlockHash         = PvAbiOffset + 6*32  // 224
	PvFieldBlockNumber       = PvAbiOffset + 7*32  // 256
	PvFieldSyncCommittee     = PvAbiOffset + 8*32  // 288
	PvFieldNextSyncCommittee = PvAbiOffset + 9*32  // 320
	PvFieldGenesisRoot       = PvAbiOffset + 10*32 // 352
	PvMinLen                 = PvAbiOffset + 11*32 // 384 — through genesisRoot

	// Sync-committee period math: SLOTS_PER_EPOCH(32) *
	// EPOCHS_PER_SYNC_COMMITTEE_PERIOD(256) = 8192 slots/period (mirrors helios
	// calc_sync_period). See syncPeriod().
	SlotsPerSyncPeriod = uint64(8192)

	// NoNextSyncCommittee — the all-0xFF sentinel the prover emits for
	// nextSyncCommitteeHash when there is no next committee yet (light_client.rs
	// MED Z-PR-M1: never emits zero, to avoid colliding with zero-initialized
	// consumer storage). submitProof skips rotating this sentinel in.
	NoNextSyncCommittee = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

// --- Admin actions ---

// InitContractParams — W1-cluster-B-schema §3 + v20 §BG LOCKED.
// Extended with:
//   - InitialBlockHash + InitialHeight (CRIT #25 atomic anchor backfill)
//   - IsTestnet (Cluster E clearTestnetState gate sentinel)
//   - GenesisRoot + InitialSyncCommitteeHash + InitialHead (beacon bootstrap)
type InitContractParams struct {
	Groth16Vk        string `json:"groth16_vk"`
	VkRoot           string `json:"vk_root"`
	Sp1VkeyHash      string `json:"sp1_vkey_hash"`
	MaxRetention     uint64 `json:"max_retention"`
	InitialHeight    uint64 `json:"initial_height"`
	InitialBlockHash string `json:"initial_block_hash"`
	IsTestnet        bool   `json:"is_testnet"`
	// The L1 chainId LABEL this verifier is bound to (e.g. 1 mainnet,
	// 11155111 Sepolia). Stamped into stored headers for account-mapping's
	// per-chain checks. Required (non-zero) at init. NOT a proof comparison —
	// chain identity is established by genesis_root + sync-committee anchoring.
	ExpectedChainId uint64 `json:"expected_chain_id"`

	// Beacon light-client bootstrap (operator supplies these from a
	// weak-subjectivity checkpoint for this chain, same provenance as
	// initial_block_hash):
	//   - GenesisRoot: genesis_validators_root, 32-byte hex (optional 0x).
	//   - InitialSyncCommitteeHash: trusted committee hash at InitialHead.
	//   - InitialHead: beacon slot of the bootstrap checkpoint (non-zero).
	GenesisRoot              string `json:"genesis_root"`
	InitialSyncCommitteeHash string `json:"initial_sync_committee_hash"`
	InitialHead              uint64 `json:"initial_head"`
}

//go:wasmexport init
func initContract(input *string) *string {
	checkOwner()

	// One-shot re-entry guard. First call (deploy-time) installs the vkey
	// state with no timelock — submitProof cannot function until init runs,
	// so a 14-day gate on first init would brick the bridge. Re-entry (after
	// vkey state is installed) is blocked entirely; subsequent vkey rotations
	// MUST go through propose() then execute() with the 400K-block timelock
	// (see timelock.go — F1 fix; this is now a real on-chain mechanism, not a
	// comment). Re-entry guard also covers the case where a rotation has run
	// (execute -> applyUpdateVkey writes KeyGroth16Vk).
	if existing := sdk.StateGetObject(KeyGroth16Vk); existing != nil && *existing != "" {
		ce.Abort(ce.ErrState, "already initialized — use propose/execute (400K-block timelock) to rotate the vkey", "init")
	}

	var params InitContractParams
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON", "init")
	}
	if params.Groth16Vk == "" || params.VkRoot == "" || params.Sp1VkeyHash == "" {
		ce.Abort(ce.ErrInput, "groth16_vk, vk_root, and sp1_vkey_hash required", "init")
	}

	// W4 Cluster B CRIT #25 + B-B-4: require initial anchor params.
	// Without these, submitProof would either reject all proofs ("anchor
	// not set") or accept a forged batch whose ParentHash matches the
	// uninitialized zero hash. The guard closes the N2 bypass window.
	if params.InitialBlockHash == "" || params.InitialHeight == 0 {
		ce.Abort(ce.ErrInput, "initial_block_hash and initial_height required for anchor", "init")
	}
	// Sanity-check the anchor hash shape (0x-prefixed 64-hex == 32 bytes).
	if !looksLikeBlockHash(params.InitialBlockHash) {
		ce.Abort(ce.ErrInput, "initial_block_hash must be 0x-prefixed 32-byte hex", "init")
	}

	// Require the bound chainId LABEL (stamped into stored headers; non-zero so
	// account-mapping's "contract chainId not configured" guard never trips).
	if params.ExpectedChainId == 0 {
		ce.Abort(ce.ErrInput, "expected_chain_id required (non-zero)", "init")
	}

	// Beacon bootstrap: pin the chain's genesis_validators_root and seed the
	// trusted sync committee + beacon head from a weak-subjectivity checkpoint.
	// The first proof must commit this genesis_root and start from this
	// committee at period(initial_head).
	if params.GenesisRoot == "" || params.InitialSyncCommitteeHash == "" || params.InitialHead == 0 {
		ce.Abort(ce.ErrInput, "genesis_root, initial_sync_committee_hash, and initial_head required for beacon bootstrap", "init")
	}
	genesisRoot := normalizeHash32(params.GenesisRoot, "genesis_root")
	initialCommittee := normalizeHash32(params.InitialSyncCommitteeHash, "initial_sync_committee_hash")

	sdk.StateSetObject(KeyGroth16Vk, params.Groth16Vk)
	sdk.StateSetObject(KeyVkRoot, params.VkRoot)
	sdk.StateSetObject(KeySp1VkeyHash, params.Sp1VkeyHash)

	retention := params.MaxRetention
	if retention == 0 {
		retention = DefaultMaxRetention
	}
	if retention < MinMaxRetention {
		ce.Abort(ce.ErrInput, "max_retention must be at least "+strconv.FormatUint(MinMaxRetention, 10)+" blocks (one day)", "init")
	}
	sdk.StateSetObject(KeyMaxRetention, strconv.FormatUint(retention, 10))

	// CRIT #25 atomic anchor: seed KeyLastBlockHash and last-height so the
	// first submitProof batch must produce a header whose ParentHash equals
	// this anchor. Seeded values come from the W0 operator runbook P5 step
	// (operator selects a recent finalized L1 block, queries its hash via
	// any trusted source, includes here at deploy time).
	sdk.StateSetObject(KeyLastBlockHash, params.InitialBlockHash)
	sdk.StateSetObject(KeyLastHeight, strconv.FormatUint(params.InitialHeight, 10))

	// Persist the chainId LABEL. Immutable after init (no setter handler — the
	// chain a verifier instance serves must not be admin-mutable).
	sdk.StateSetObject(KeyExpectedChainId, strconv.FormatUint(params.ExpectedChainId, 10))

	// Beacon bootstrap state: pin genesis_root, seed the trusted committee for
	// the bootstrap period, and set the initial beacon head.
	sdk.StateSetObject(KeyGenesisRoot, genesisRoot)
	sdk.StateSetObject(SyncCommitteePrefix+strconv.FormatUint(syncPeriod(params.InitialHead), 10), initialCommittee)
	sdk.StateSetObject(KeyBeaconHead, strconv.FormatUint(params.InitialHead, 10))

	// v20 §BG: testnet sentinel for Cluster E's clearTestnetState. ABSENCE
	// of this key == mainnet; presence == testnet. Mainnet deploys MUST
	// pass IsTestnet=false; clearTestnetState reads this sentinel.
	if params.IsTestnet {
		sdk.StateSetObject("is_testnet", "true")
	}

	return nil
}

// looksLikeBlockHash — minimal shape check for InitialBlockHash. Full
// 32-byte/hex validation happens implicitly at the first submitProof
// (the comparison vs parsed[0].ParentHash will fail loudly on any
// malformed value).
func looksLikeBlockHash(s string) bool {
	if len(s) != 66 {
		return false
	}
	if s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// normalizeHash32 validates a 32-byte value (optional 0x prefix) and returns it
// as canonical bare lowercase hex; aborts on bad shape. Round-tripping through
// hex.Decode/Encode guarantees the stored form matches parseProvenFields'
// hex.EncodeToString output byte-for-byte (so genesis/committee compares work).
func normalizeHash32(h, field string) string {
	if len(h) >= 2 && (h[:2] == "0x" || h[:2] == "0X") {
		h = h[2:]
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		ce.Abort(ce.ErrInput, field+" must be 32-byte hex (64 chars, optional 0x prefix)", "init")
	}
	return hex.EncodeToString(b)
}

// applySetExpectedElfHash — W4 Cluster B HIGH #22 Site 12: pins the SHA-256
// of the SP1 ELF binary the prover is allowed to use. Prover startup reads
// this and fatal-exits on mismatch. Fund-affecting (wrong hash = bridge halt;
// malicious hash + compromised prover = attacker controls all ZK-verified
// Ethereum state).
//
// F1 fix: ROTATIONS are reachable ONLY via execute() after the 400K-block
// propose/execute timelock. The FIRST pin (below) is allowed instantly during
// deploy ramp-up — there is no trusted value to rotate FROM (the prover runs
// UNPINNED until this is set), so an instant first pin only ADDS protection.
// Previously this was an instant owner-only write for ALL changes (the hole),
// with a comment claiming a timelock that did not exist.
func applySetExpectedElfHash(payload string) {
	var params struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal([]byte(payload), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON", "setExpectedElfHash")
	}
	sdk.StateSetObject(KeyExpectedElfHash, normalizeElfHash(params.Hash))
}

// setExpectedElfHash — FIRST-PIN ONLY (instant, owner-gated). Allows the
// operator to pin the SP1 ELF hash during deploy ramp-up without waiting the
// 400K-block timelock (the prover is UNPINNED until this runs, so an instant
// first pin only adds protection — there is nothing trusted to rotate from).
// Once set, this aborts and directs rotations through propose/execute, which
// IS timelocked. Mirrors init's one-shot for the vkey.
//
//go:wasmexport setExpectedElfHash
func setExpectedElfHash(input *string) *string {
	checkOwner()
	if existing := sdk.StateGetObject(KeyExpectedElfHash); existing != nil && *existing != "" {
		ce.Abort(ce.ErrState, "elf hash already set — use propose/execute (400K-block timelock) to rotate", "setExpectedElfHash")
	}
	if input == nil || *input == "" {
		ce.Abort(ce.ErrInput, "setExpectedElfHash: empty payload", "setExpectedElfHash")
	}
	applySetExpectedElfHash(*input)
	return nil
}

// normalizeElfHash validates the 32-byte SHA-256 hex (optional 0x prefix) and
// returns the bare hex; aborts on bad shape. Shared by applySetExpectedElfHash
// and propose()-time payload validation (timelock.go).
func normalizeElfHash(h string) string {
	if len(h) >= 2 && (h[:2] == "0x" || h[:2] == "0X") {
		h = h[2:]
	}
	if len(h) != 64 {
		ce.Abort(ce.ErrInput, "hash must be 32-byte hex (64 chars, optional 0x prefix)", "setExpectedElfHash")
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			ce.Abort(ce.ErrInput, "hash contains non-hex character", "setExpectedElfHash")
		}
	}
	return h
}

// applyUpdateVkey — rotates the Groth16 / SP1 verification key (the entire ZK
// trust root).
//
// F1 fix: NO LONGER a direct wasmexport. Reachable ONLY via execute() after
// the 400K-block propose/execute timelock (see timelock.go). Previously this
// was an instant owner-only write with a comment falsely claiming a timelock —
// an owner-key compromise could rotate the vkey and forge L1 state with zero
// reaction window. The timelock now gives watchers ~14 days to react.
func applyUpdateVkey(payload string) {
	var params struct {
		Groth16Vk   string `json:"groth16_vk"`
		VkRoot      string `json:"vk_root"`
		Sp1VkeyHash string `json:"sp1_vkey_hash"`
	}
	if err := json.Unmarshal([]byte(payload), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON", "updateVkey")
		return
	}
	// review6 M10: all three vkey components MUST rotate together. The prior
	// per-field write let a propose/execute push only Groth16Vk (or VkRoot,
	// or Sp1VkeyHash) and leave the others on the previous rotation, mixing
	// keying material from two different proving setups — submitProof would
	// then accept proofs that pass one component's check but were never
	// produced under the matching counterpart. Mirror init's all-required
	// rule.
	if params.Groth16Vk == "" || params.VkRoot == "" || params.Sp1VkeyHash == "" {
		ce.Abort(ce.ErrInput, "updateVkey requires all three fields: groth16_vk, vk_root, sp1_vkey_hash", "updateVkey")
		return
	}
	sdk.StateSetObject(KeyGroth16Vk, params.Groth16Vk)
	sdk.StateSetObject(KeyVkRoot, params.VkRoot)
	sdk.StateSetObject(KeySp1VkeyHash, params.Sp1VkeyHash)
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

	// E5: one gap at a time; the operator backfills right after its proof.
	if g := sdk.StateGetObject(KeyGapWant); g != nil && *g != "" {
		ce.Abort(ce.ErrTransaction, "a header gap is open below the last proven block; fill it with submitHeaders first", "submitProof")
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

	// MED #85 (M31-G3) — cheap shape gate, runs BEFORE the expensive host verify.
	//
	// public_values is the ABI-encoded ProofOutputs, decoded as hex below; it
	// must be even-length hex and long enough for parseProvenFields (>=
	// PvMinLen bytes). Rejecting obviously-malformed submissions here
	// avoids spending the costly Sp1VerifyGroth16 pairing check on inputs that
	// the post-verify decode would reject anyway. No valid proof is dropped: the
	// post-verify decode (parseProvenFields) requires exactly this minimum.
	//
	// NOTE ON THE RESIDUAL DoS BOUND (do not add a per-block contract counter):
	// the shape gate cannot stop a "correctly-sized garbage proof" — only the
	// host pairing check can tell a valid proof from correctly-sized garbage, so
	// such a submission necessarily reaches Sp1VerifyGroth16. A per-block counter
	// kept in contract state CANNOT bound this: submitProof is permissionless and
	// a failed verify ABORTS, which reverts the whole transaction (state engine
	// commits contract state only on success — state_engine.go:1878-1895), so any
	// counter increment is discarded on exactly the attack case. The aggregate
	// Groth16 work an attacker can force per block is instead bounded at the HOST
	// layer by RC/gas: the runtime charges CYCLE_GAS_PER_RC*10 for every
	// sp1_verify_groth16 invocation regardless of proof validity
	// (modules/wasm/sdk/sdk.go:737,739), and that RC charge is applied to the
	// payer OUTSIDE the revert path (state_engine.go:1813-1814), so it survives
	// the abort and is capped by the payer's RC budget. That host-layer bound is
	// the load-bearing mitigation; this contract-side gate only short-circuits
	// the trivially-malformed case before paying for the verify.
	if len(params.PublicValues)%2 != 0 || len(params.PublicValues) < PvMinLen*2 {
		ce.Abort(ce.ErrInput, "public_values too short or odd-length hex", "submitProof")
	}

	// 1. Verify the ZK proof
	result := sdk.Sp1VerifyGroth16(params.Proof, params.PublicValues, *sp1VkeyHash, *groth16Vk, *vkRoot)
	if result != "true" {
		ce.Abort(ce.ErrTransaction, "proof verification failed", "submitProof")
	}

	// 2. Decode publicValues into the proven beacon + execution fields.
	pvBytes, err := hex.DecodeString(params.PublicValues)
	if err != nil {
		ce.Abort(ce.ErrInvalidHex, "invalid public_values hex", "submitProof")
	}
	pf, perr := parseProvenFields(pvBytes)
	if perr != nil {
		ce.CustomAbort(ce.Prepend(perr, "submitProof"))
	}

	// 2a. CHAIN BINDING — genesis_validators_root pin. The proof must be for the
	// beacon chain this verifier was bootstrapped against. genesisRoot is the BLS
	// signing-domain root the sync-committee signatures were verified under
	// in-circuit, so an attacker's fake chain carries a different root.
	genesisPtr := sdk.StateGetObject(KeyGenesisRoot)
	if genesisPtr == nil || *genesisPtr == "" {
		ce.Abort(ce.ErrInitialization, "genesis_root not set; verifier must be initialized with genesis_root", "submitProof")
	}
	if pf.genesisRoot != *genesisPtr {
		ce.Abort(ce.ErrTransaction, "proof genesis_validators_root does not match verifier's bound chain", "submitProof")
	}

	// 2b. CHAIN BINDING — sync-committee anchoring (the load-bearing check). The
	// proof must START from a committee this verifier already trusts:
	// prevSyncCommitteeHash must equal the stored committee for period(prevHead).
	// Without this, an attacker could prove from a self-chosen (fake) committee.
	prevPeriodKey := SyncCommitteePrefix + strconv.FormatUint(syncPeriod(pf.prevHead), 10)
	trustedPtr := sdk.StateGetObject(prevPeriodKey)
	if trustedPtr == nil || *trustedPtr == "" {
		ce.Abort(ce.ErrTransaction, "no trusted sync committee for the proof's prev period", "submitProof")
	}
	if pf.prevSyncCommittee != *trustedPtr {
		ce.Abort(ce.ErrTransaction, "proof's prev sync committee is not trusted", "submitProof")
	}

	// 2c. Forward progress: the beacon head must strictly advance (anti-replay /
	// anti-rollback). Rejects re-submitting an old proof or rolling the head back.
	if pf.newHead <= getBeaconHead() {
		ce.Abort(ce.ErrTransaction, "beacon head not advancing", "submitProof")
	}

	// RV-4 (RV re-verify): bind prevHead to the stored beacon head. Without this,
	// 2b only required the proof's start committee to be *some* trusted period —
	// so a proof planted at a future period (via the committee-injection below)
	// could be consumed out of order. Requiring prevHead == the last accepted
	// head forces every proof to continue the one canonical chain this verifier
	// has already accepted, closing the "start from any trusted period" gap that
	// the missing upstream #54 reset would otherwise open. The bootstrap proof
	// (beaconHead == InitialHead set at init) must start exactly from it.
	if pf.prevHead != getBeaconHead() {
		ce.Abort(ce.ErrTransaction, "proof prev_head does not continue the stored beacon head", "submitProof")
	}

	// 2d. The chainId LABEL stamped into stored headers comes from this verifier's
	// own config (NOT the proof) — chain identity is already proven above.
	// account-mapping cross-checks this label against its own configured chainId.
	expectedChainPtr := sdk.StateGetObject(KeyExpectedChainId)
	if expectedChainPtr == nil || *expectedChainPtr == "" {
		ce.Abort(ce.ErrInitialization, "expected_chain_id not set; verifier must be initialized with expected_chain_id", "submitProof")
	}
	headerChainId, ecErr := strconv.ParseUint(*expectedChainPtr, 10, 64)
	if ecErr != nil {
		ce.Abort(ce.ErrState, "stored expected_chain_id is not a valid uint64", "submitProof")
	}

	// W4 Cluster B CRIT #25 — anchor check.
	// Read the cross-batch anchor BEFORE parsing headers. Without an
	// anchor (empty or zero hash), every prior submission state is
	// untrusted and a forged "first batch" could inject arbitrary state.
	// initContract MUST have set this; the InitContractParams.
	// InitialBlockHash guard at init time prevents zero-anchor deploys.
	anchorPtr := sdk.StateGetObject(KeyLastBlockHash)
	if anchorPtr == nil || *anchorPtr == "" || *anchorPtr == "0x0000000000000000000000000000000000000000000000000000000000000000" {
		ce.Abort(ce.ErrInitialization, "lastBlockHash anchor not set; call initContract with initial_block_hash", "submitProof")
	}
	anchorHex := *anchorPtr
	// Strip 0x prefix to compare against the keccak hex (which is bare hex).
	if len(anchorHex) >= 2 && (anchorHex[0:2] == "0x" || anchorHex[0:2] == "0X") {
		anchorHex = anchorHex[2:]
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

	// W4 Cluster B CRIT #25 — cross-batch parent check.
	// The first header in this batch MUST extend the previously-stored
	// chain at exactly `parsed[0].ParentHash == lastBlockHash`. This
	// closes the "unbound prevHeader" gap that let any well-formed proof
	// for ANY hash chain land regardless of the contract's prior history.
	//
	// E5: a batch that does not reach the anchor (its first header is above
	// the stored tip + 1) opens a gap instead, filled by submitHeaders: every
	// header stays keccak-bound to this proven block, and the gap closes only
	// when the backfill meets the anchor.
	lastHeight := getLastHeight()
	contiguous := hex.EncodeToString(parsed[0].ParentHash[:]) == anchorHex
	if !contiguous && parsed[0].BlockNumber <= lastHeight+1 {
		ce.Abort(ce.ErrTransaction, "parent hash of first header does not match stored anchor (lastBlockHash)", "submitProof")
	}

	// 4. Bind the last header's RLP and extracted fields to the proof's public inputs.
	if hashes[lastIdx] != pf.blockHash {
		ce.Abort(ce.ErrTransaction, "keccak256(last header RLP) != proven block hash", "submitProof")
	}
	if parsed[lastIdx].BlockNumber != pf.blockNumber {
		ce.Abort(ce.ErrTransaction, "last header block number ("+
			strconv.FormatUint(parsed[lastIdx].BlockNumber, 10)+
			") != proven block number ("+
			strconv.FormatUint(pf.blockNumber, 10)+")", "submitProof")
	}
	if hex.EncodeToString(parsed[lastIdx].StateRoot[:]) != pf.stateRoot {
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
	// Every stored header carries the verifier's configured chainId LABEL
	// (headerChainId) at bytes 129-136. account-mapping reads it on the ERC-20
	// receipt path and cross-checks it against its own configured chainId.
	maxRetention := getMaxRetention()
	if !contiguous {
		sdk.StateSetObject(KeyGapWant, hex.EncodeToString(parsed[0].ParentHash[:]))
		sdk.StateSetObject(KeyGapLow, strconv.FormatUint(parsed[0].BlockNumber, 10))
		sdk.StateSetObject(KeyGapBase, strconv.FormatUint(lastHeight, 10))
		sdk.StateSetObject(KeyGapAnchor, anchorHex)
		lastHeight = parsed[0].BlockNumber - 1
	}
	for i := range parsed {
		p := parsed[i]
		if lastHeight > 0 && p.BlockNumber != lastHeight+1 {
			ce.Abort(ce.ErrInput, "block heights must be sequential", "submitProof")
		}
		if i > 0 && p.BlockNumber != parsed[i-1].BlockNumber+1 {
			ce.Abort(ce.ErrInput, "headers not sequential within batch", "submitProof")
		}

		storeHeader(p.BlockNumber, p.StateRoot, p.TxRoot, p.RcptRoot, p.BaseFeePerGas, p.GasLimit, p.Timestamp, headerChainId)
		lastHeight = p.BlockNumber

		if p.BlockNumber > maxRetention {
			sdk.StateDeleteObject(KeyBlockPrefix + strconv.FormatUint(p.BlockNumber-maxRetention, 10))
		}
	}

	sdk.StateSetObject(KeyLastHeight, strconv.FormatUint(lastHeight, 10))

	// CHAIN BINDING — rotate the trusted sync-committee set forward and advance
	// the beacon head, now that every check has passed. Store the current
	// committee for period(newHead); store the next committee for the following
	// period unless it is the prover's "no next committee" sentinel.
	curPeriod := syncPeriod(pf.newHead)
	// RV-4 (RV re-verify): write committees SET-IF-EMPTY with a mismatch revert,
	// mirroring upstream SP1Helios.sol. The SP1 program does not reset
	// store.next_sync_committee between proofs (missing upstream #54), so a
	// prover could commit an UNVERIFIED next committee. Pre-fix this verifier
	// stored sc-{curPeriod+1} unconditionally, so that bogus committee became
	// trusted and a second proof could start from it and forge finality. Only
	// writing an empty slot — and reverting if a proof ever disagrees with a
	// committee already trusted for a period — means a committee can only be set
	// by the proof that first legitimately rotates into its period.
	storeTrustedCommittee(curPeriod, pf.syncCommittee)
	if pf.nextSyncCommittee != NoNextSyncCommittee {
		storeTrustedCommittee(curPeriod+1, pf.nextSyncCommittee)
	}
	sdk.StateSetObject(KeyBeaconHead, strconv.FormatUint(pf.newHead, 10))

	// W4 Cluster B CRIT #25 — update anchor for the next batch. Use the
	// hex of the last header's keccak so the next call's parsed[0].
	// ParentHash check has a canonical form to match against. Prepend 0x
	// for consistency with the InitialBlockHash format (initContract
	// validates 0x-prefixed input; stored value retains the prefix so
	// off-chain tooling reads back identical to what was supplied).
	sdk.StateSetObject(KeyLastBlockHash, "0x"+hashes[lastIdx])
	return nil
}

// SubmitHeadersParams carries a backfill batch for an open gap, oldest first.
type SubmitHeadersParams struct {
	Headers []SubmittedHeader `json:"headers"`
}

// submitHeaders backfills an open gap (E5) from its top down. The batch's last
// header must hash to the gap's wanted hash (the parent of the lowest stored
// header, which is keccak-bound to a proven block), and the batch must chain
// by parent hash with sequential heights; so every stored header descends to a
// proven block. Permissionless: there is nothing to choose, only the one chain
// that hashes into the proof. The gap closes when the batch meets the stored
// chain below it; a batch that reaches that height without linking to it
// fails closed.
//
//go:wasmexport submitHeaders
func submitHeaders(input *string) *string {
	var params SubmitHeadersParams
	if err := json.Unmarshal([]byte(*input), &params); err != nil {
		ce.Abort(ce.ErrJson, "invalid JSON: "+err.Error(), "submitHeaders")
	}
	if len(params.Headers) == 0 || len(params.Headers) > MaxHeadersPerTx {
		ce.Abort(ce.ErrInput, "1 to "+strconv.Itoa(MaxHeadersPerTx)+" headers required", "submitHeaders")
	}
	wantPtr := sdk.StateGetObject(KeyGapWant)
	if wantPtr == nil || *wantPtr == "" {
		ce.Abort(ce.ErrTransaction, "no header gap is open", "submitHeaders")
	}
	low, _ := strconv.ParseUint(stateOr(KeyGapLow, "0"), 10, 64)
	base, _ := strconv.ParseUint(stateOr(KeyGapBase, "0"), 10, 64)
	gapAnchor := stateOr(KeyGapAnchor, "")

	lastIdx := len(params.Headers) - 1
	parsed := make([]parsedHeader, len(params.Headers))
	hashes := make([]string, len(params.Headers))
	for i, h := range params.Headers {
		parsed[i] = parseHeader(h.RlpHex)
		hashes[i] = sdk.Keccak256(h.RlpHex)
	}
	if hashes[lastIdx] != *wantPtr || parsed[lastIdx].BlockNumber+1 != low {
		ce.Abort(ce.ErrTransaction, "last header is not the parent of the lowest backfilled header", "submitHeaders")
	}
	for i := lastIdx - 1; i >= 0; i-- {
		if hex.EncodeToString(parsed[i+1].ParentHash[:]) != hashes[i] || parsed[i].BlockNumber+1 != parsed[i+1].BlockNumber {
			ce.Abort(ce.ErrTransaction, "hash chain broken at block "+strconv.FormatUint(parsed[i].BlockNumber, 10), "submitHeaders")
		}
	}
	if parsed[0].BlockNumber <= base {
		ce.Abort(ce.ErrInput, "backfill reaches below the stored chain", "submitHeaders")
	}
	chainId, _ := strconv.ParseUint(stateOr(KeyExpectedChainId, "0"), 10, 64)
	// Same retention as submitProof: keep the last maxRetention heights below
	// the proven tip. A backfilled height already outside it is linked, not
	// stored, and the height maxRetention below each one is pruned (submitProof
	// pruned only below the heights it stored).
	tip := getLastHeight()
	maxRetention := getMaxRetention()
	for _, p := range parsed {
		if p.BlockNumber+maxRetention > tip {
			storeHeader(p.BlockNumber, p.StateRoot, p.TxRoot, p.RcptRoot, p.BaseFeePerGas, p.GasLimit, p.Timestamp, chainId)
		}
		if p.BlockNumber > maxRetention {
			sdk.StateDeleteObject(KeyBlockPrefix + strconv.FormatUint(p.BlockNumber-maxRetention, 10))
		}
	}
	if parsed[0].BlockNumber == base+1 {
		if hex.EncodeToString(parsed[0].ParentHash[:]) != gapAnchor {
			ce.Abort(ce.ErrTransaction, "backfill does not meet the stored chain (parent of block "+
				strconv.FormatUint(parsed[0].BlockNumber, 10)+" is not the stored tip)", "submitHeaders")
		}
		for _, k := range []string{KeyGapWant, KeyGapLow, KeyGapBase, KeyGapAnchor} {
			sdk.StateDeleteObject(k)
		}
		return nil
	}
	sdk.StateSetObject(KeyGapWant, hex.EncodeToString(parsed[0].ParentHash[:]))
	sdk.StateSetObject(KeyGapLow, strconv.FormatUint(parsed[0].BlockNumber, 10))
	return nil
}

// stateOr reads a state key, or def when unset (the runtime reads a missing
// key as "").
func stateOr(key, def string) string {
	if v := sdk.StateGetObject(key); v != nil && *v != "" {
		return *v
	}
	return def
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

// parsedHeader — W4 Cluster B Site 4 + §AW disambiguation.
// ChainId field added but NOT populated by parseHeader (Ethereum RLP
// block headers have no chainId field — adding RLP extraction would be
// wrong). ChainId here is populated from parseProvenFields' return
// value (slot 11 of ProofOutputs) in submitProof, then forwarded into
// storeHeader. This struct's ChainId is informational only; the
// authoritative chainId is the function-local provenChainId that the
// submitProof loop passes into storeHeader.
type parsedHeader struct {
	BlockNumber   uint64
	ParentHash    [32]byte
	StateRoot     [32]byte
	TxRoot        [32]byte
	RcptRoot      [32]byte
	GasLimit      uint64
	Timestamp     uint64
	BaseFeePerGas uint64
	ChainId       uint64 // populated post-parseProvenFields, NOT from RLP
}

func parseHeader(rlpHex string) parsedHeader {
	rlpBytes, err := hex.DecodeString(rlpHex)
	if err != nil {
		ce.Abort(ce.ErrInvalidHex, "invalid rlp_hex", "submitProof")
		return parsedHeader{} // L6 review6: defense-in-depth for no-op Abort stub
	}
	payloadStart, _, _, isList := readRLPItem(rlpBytes, 0)
	if !isList {
		ce.Abort(ce.ErrInput, "rlp not a list", "submitProof")
		return parsedHeader{} // L6 review6: defense-in-depth for no-op Abort stub
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
//
// L6 review6: every `ce.Abort` is followed by an explicit zero-return so a
// no-op Abort stub (Go test build) can't fall through and return
// out-of-bounds indices to the caller. Real WASM host terminates on Abort
// so this is defense-in-depth for the test path.
func readRLPItem(buf []byte, offset int) (int, int, int, bool) {
	if offset >= len(buf) {
		ce.Abort(ce.ErrInput, "rlp truncated", "submitProof")
		return 0, 0, 0, false
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
			return 0, 0, 0, false
		}
		return offset + 1, l, offset + 1 + l, false
	case b < 0xc0:
		ll := int(b - 0xb7)
		if offset+1+ll > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-string len truncated", "submitProof")
			return 0, 0, 0, false
		}
		l := readRLPLen(buf[offset+1 : offset+1+ll])
		end := offset + 1 + ll + l
		if end > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-string truncated", "submitProof")
			return 0, 0, 0, false
		}
		return offset + 1 + ll, l, end, false
	case b < 0xf8:
		l := int(b - 0xc0)
		if offset+1+l > len(buf) {
			ce.Abort(ce.ErrInput, "rlp short-list truncated", "submitProof")
			return 0, 0, 0, false
		}
		return offset + 1, l, offset + 1 + l, true
	default:
		ll := int(b - 0xf7)
		if offset+1+ll > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-list len truncated", "submitProof")
			return 0, 0, 0, false
		}
		l := readRLPLen(buf[offset+1 : offset+1+ll])
		end := offset + 1 + ll + l
		if end > len(buf) {
			ce.Abort(ce.ErrInput, "rlp long-list truncated", "submitProof")
			return 0, 0, 0, false
		}
		return offset + 1 + ll, l, end, true
	}
}

// readRLPLen decodes a big-endian RLP length descriptor.
//
// MED #65 (A1-F4): the previous `len(buf) > 8` guard let a length up to 8 bytes
// through and accumulated it into a plain `int`. On the 32-bit wasm-unknown
// target any descriptor wider than 4 bytes (value > 2^31) overflows `int` to a
// NEGATIVE number; readRLPItem then computes a negative `end`, its
// `end > len(buf)` bound check passes (negative < len), and a negative length is
// returned that panics the contract on the next slice — a permissionless
// submitProof DoS. The fix accumulates in uint64 (cannot overflow for ≤8 bytes)
// and rejects anything above MaxRLPItemLen BEFORE narrowing to int, so the
// returned value is always in [0, 16 MiB].
func readRLPLen(buf []byte) int {
	if len(buf) > 8 {
		ce.Abort(ce.ErrInput, "rlp len overflow", "submitProof")
		return 0 // L6 review6: defense-in-depth for no-op Abort stub
	}
	var v uint64
	for _, b := range buf {
		v = (v << 8) | uint64(b)
	}
	if v > MaxRLPItemLen {
		ce.Abort(ce.ErrInput, "rlp item length exceeds maximum", "submitProof")
		return 0 // defense-in-depth for no-op Abort stub
	}
	return int(v)
}

func readBytes32(buf []byte, offset int, out *[32]byte) int {
	s, l, next, isList := readRLPItem(buf, offset)
	if isList {
		ce.Abort(ce.ErrInput, "rlp expected string, got list", "submitProof")
		return next // L6 review6: defense-in-depth for no-op Abort stub
	}
	if l != 32 {
		ce.Abort(ce.ErrInput, "rlp expected 32-byte field", "submitProof")
		return next // L6 review6: defense-in-depth for no-op Abort stub
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

// HeaderVersionV1 + storeHeader — W4 Cluster B Site 4/6 unified layout.
// The serialized form MUST match the account-mapping EthBlockHeader
// serialization byte-for-byte (137 bytes total, version+128+chainId).
// account-mapping reads from this contract's KeyBlockPrefix via the
// VerifierContractIdKey indirection — any layout drift would silently
// misread chainId or baseFee.
//
// Layout (LOCKED, mirrors account-mapping/contract/blocklist/blocks.go):
//
//	[version:1][blockNumber:8][stateRoot:32][txRoot:32][rcptRoot:32]
//	[baseFee:8][gasLimit:8][timestamp:8][chainId:8] = 137 bytes.
const HeaderVersionV1 byte = 0x01
const HeaderSerializedSize = 137

func storeHeader(blockNumber uint64, stateRoot, txRoot, rcptRoot [32]byte, baseFee, gasLimit, timestamp, chainId uint64) {
	buf := make([]byte, 0, HeaderSerializedSize)
	buf = append(buf, HeaderVersionV1)
	buf = appendUint64(buf, blockNumber)
	buf = append(buf, stateRoot[:]...)
	buf = append(buf, txRoot[:]...)
	buf = append(buf, rcptRoot[:]...)
	buf = appendUint64(buf, baseFee)
	buf = appendUint64(buf, gasLimit)
	buf = appendUint64(buf, timestamp)
	// W4 Cluster B Site 6: appended chainId; populated from the proven
	// slot-11 value of ProofOutputs. account-mapping/blocklist/blocks.go
	// DeserializeHeader reads this at byte offset 129-136.
	buf = appendUint64(buf, chainId)
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
	env := sdk.GetEnv()
	caller := env.Caller.String()
	owner := sdk.GetEnvKey("contract.owner")
	// review6 closure (F11 / INFO-11): reject the degenerate
	// "owner=='' && caller==''" pass-through. Without this, an
	// unconfigured contract (no owner set) would let any unauthenticated
	// caller execute owner-only handlers. Single explicit guard before
	// the equality check.
	if owner == nil || *owner == "" {
		ce.Abort(ce.ErrNoPermission, "owner not set on this contract", "auth")
		return
	}
	if caller != *owner {
		ce.Abort(ce.ErrNoPermission, "owner required", "auth")
	}
	// A2: a posting-only signature makes its signer the Caller too, so the
	// owner's posting key (the one handed to front ends) passed this gate: it
	// could pin the ELF hash and propose / execute a vkey rotation, the whole
	// ZK trust root. Require the owner's active authority, as the
	// account-mapping bridge and the BTC mapping contract do.
	if !slices.Contains(env.Sender.RequiredAuths, env.Caller) {
		ce.Abort(ce.ErrNoPermission, "owner active authority required", "auth")
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

// provenFields holds the values parseProvenFields extracts from the SP1
// program's ABI-encoded ProofOutputs. The 32-byte fields are bare lowercase
// hex; beacon slots and the execution block number are uint64 read from the low
// 8 bytes of their 32-byte ABI slot.
type provenFields struct {
	stateRoot         string // executionStateRoot (slot 5)
	blockHash         string // executionBlockHash (slot 6)
	genesisRoot       string // genesis_validators_root (slot 10)
	prevSyncCommittee string // committee that signed the proof (slot 2)
	syncCommittee     string // current committee after updates (slot 8)
	nextSyncCommittee string // next-period committee, or 0xFF sentinel (slot 9)
	blockNumber       uint64 // executionBlockNumber (slot 7)
	prevHead          uint64 // beacon slot the proof started from (slot 1)
	newHead           uint64 // beacon slot the proof advanced to (slot 3)
}

// parseProvenFields decodes the SP1 ProofOutputs bytes. Returns a non-nil
// *ContractError on any structural problem. No SDK calls — pure function, safe
// to test under standard go test. See the ABI layout note on the Pv* constants
// and sp1-helios-magi/primitives/src/types.rs for the authoritative sol struct.
func parseProvenFields(pvBytes []byte) (provenFields, *ce.ContractError) {
	var pf provenFields
	if len(pvBytes) < PvMinLen {
		return pf, ce.NewContractError(ce.ErrInput, "public_values too short for ABI fields")
	}
	if readUint64BE(pvBytes[24:32]) != PvAbiOffset {
		return pf, ce.NewContractError(ce.ErrInput, "unexpected ABI tuple offset (expected 32)")
	}
	pf.stateRoot = hex.EncodeToString(pvBytes[PvFieldStateRoot : PvFieldStateRoot+32])
	pf.blockHash = hex.EncodeToString(pvBytes[PvFieldBlockHash : PvFieldBlockHash+32])
	pf.genesisRoot = hex.EncodeToString(pvBytes[PvFieldGenesisRoot : PvFieldGenesisRoot+32])
	pf.prevSyncCommittee = hex.EncodeToString(pvBytes[PvFieldPrevSyncCommittee : PvFieldPrevSyncCommittee+32])
	pf.syncCommittee = hex.EncodeToString(pvBytes[PvFieldSyncCommittee : PvFieldSyncCommittee+32])
	pf.nextSyncCommittee = hex.EncodeToString(pvBytes[PvFieldNextSyncCommittee : PvFieldNextSyncCommittee+32])
	pf.blockNumber = readUint64BE(pvBytes[PvFieldBlockNumber+24 : PvFieldBlockNumber+32])
	pf.prevHead = readUint64BE(pvBytes[PvFieldPrevHead+24 : PvFieldPrevHead+32])
	pf.newHead = readUint64BE(pvBytes[PvFieldNewHead+24 : PvFieldNewHead+32])
	return pf, nil
}

// storeTrustedCommittee writes the trusted sync-committee hash for a period
// SET-IF-EMPTY (RV-4). If the slot is empty it is written; if it already holds
// the same hash it is a no-op; if it holds a DIFFERENT hash the proof is trying
// to overwrite an already-trusted committee (the committee-injection path the
// missing upstream #54 reset enables) and the whole submission is reverted.
func storeTrustedCommittee(period uint64, committee string) {
	key := SyncCommitteePrefix + strconv.FormatUint(period, 10)
	existing := sdk.StateGetObject(key)
	if existing != nil && *existing != "" {
		if *existing != committee {
			ce.Abort(ce.ErrTransaction, "sync committee for this period is already trusted and differs — refusing to overwrite", "submitProof")
		}
		return
	}
	sdk.StateSetObject(key, committee)
}

// syncPeriod maps a beacon slot to its sync-committee period.
func syncPeriod(slot uint64) uint64 { return slot / SlotsPerSyncPeriod }

// getBeaconHead returns the last accepted finalized beacon slot (0 if unset).
func getBeaconHead() uint64 {
	data := sdk.StateGetObject(KeyBeaconHead)
	if data == nil || *data == "" {
		return 0
	}
	v, _ := strconv.ParseUint(*data, 10, 64)
	return v
}

// ===== F1 fix: admin propose/execute timelock (was contract/timelock.go) =====
const (
	KeyProposalCounter = "proposal_next_id"
	ProposalPrefix     = "pr-"

	// Fund-affecting timelock (~14 days at ~3s blocks) — same class as
	// account-mapping's TimelockLong for setVault/setVerifierContract/vkey.
	TimelockLong = uint64(400_000)
	// Auto-expire window after execHeight (7 days) so stale proposals can be
	// garbage-collected and cannot be executed long after their context.
	ExpireWindowBlocks = uint64(201_600)

	StatusPending   = uint8(0)
	StatusAccepted  = uint8(1)
	StatusCancelled = uint8(2)
	StatusExpired   = uint8(3)
)

type PendingProposal struct {
	ProposalId   uint64 `json:"proposal_id"`
	Action       string `json:"action"`
	PayloadHash  string `json:"payload_hash"` // keccak256 hex of Payload bytes
	Proposer     string `json:"proposer"`
	QueueHeight  uint64 `json:"queue_height"`
	ExecHeight   uint64 `json:"exec_height"`
	ExpireHeight uint64 `json:"expire_height"`
	Payload      string `json:"payload"` // raw JSON for the action handler
	Status       uint8  `json:"status"`
}

// timelockFor — only the two fund-affecting verifier actions are timelocked
// and propose-able. Anything else is rejected (no silent passthrough).
func timelockFor(action string) (uint64, bool) {
	switch action {
	case "updateVkey", "setExpectedElfHash":
		return TimelockLong, true
	default:
		return 0, false
	}
}

func proposalKey(id uint64) string {
	return ProposalPrefix + strconv.FormatUint(id, 10)
}

// hashPayload — keccak256 of the raw payload bytes. sdk.Keccak256 takes a hex
// string, so the bytes are hex-encoded first.
func hashPayload(payload string) string {
	return sdk.Keccak256(hex.EncodeToString([]byte(payload)))
}

func nextProposalId() uint64 {
	s := sdk.StateGetObject(KeyProposalCounter)
	var id uint64
	if s != nil {
		id, _ = strconv.ParseUint(*s, 10, 64)
	}
	if id == 0 {
		id = 1
	}
	sdk.StateSetObject(KeyProposalCounter, strconv.FormatUint(id+1, 10))
	return id
}

func loadProposal(id uint64) *PendingProposal {
	d := sdk.StateGetObject(proposalKey(id))
	if d == nil {
		return nil
	}
	pp := &PendingProposal{}
	if err := json.Unmarshal([]byte(*d), pp); err != nil {
		return nil
	}
	return pp
}

func storeProposal(pp *PendingProposal) {
	b, _ := json.Marshal(pp)
	sdk.StateSetObject(proposalKey(pp.ProposalId), string(b))
}

// propose — owner queues a fund-affecting action. Returns {proposal_id, exec_height}.
//
//go:wasmexport propose
func propose(input *string) *string {
	checkOwner()
	if input == nil || *input == "" {
		ce.Abort(ce.ErrInput, "propose: empty payload", "propose")
	}
	var req struct {
		Action  string `json:"action"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(*input), &req); err != nil {
		ce.Abort(ce.ErrJson, "propose: invalid JSON", "propose")
	}
	timelock, ok := timelockFor(req.Action)
	if !ok {
		ce.Abort(ce.ErrInput, "propose: unknown or non-timelocked action", "propose")
	}
	// Validate the action payload up-front so a malformed proposal cannot
	// sit for 14 days only to fail at execute time.
	validateActionPayload(req.Action, req.Payload)

	bh := sdk.GetEnv().BlockHeight
	id := nextProposalId()
	execH := bh + timelock
	pp := &PendingProposal{
		ProposalId:   id,
		Action:       req.Action,
		PayloadHash:  hashPayload(req.Payload),
		Proposer:     sdk.GetEnv().Caller.String(),
		QueueHeight:  bh,
		ExecHeight:   execH,
		ExpireHeight: execH + ExpireWindowBlocks,
		Payload:      req.Payload,
		Status:       StatusPending,
	}
	storeProposal(pp)
	out := `{"proposal_id":` + strconv.FormatUint(id, 10) + `,"exec_height":` + strconv.FormatUint(execH, 10) + `}`
	return &out
}

// execute — owner enacts a proposal once its timelock has elapsed.
//
//go:wasmexport execute
func execute(input *string) *string {
	checkOwner()
	var req struct {
		ProposalId uint64 `json:"proposal_id"`
	}
	if input == nil || json.Unmarshal([]byte(*input), &req) != nil {
		ce.Abort(ce.ErrInput, "execute: invalid JSON", "execute")
	}
	pp := loadProposal(req.ProposalId)
	if pp == nil {
		ce.Abort(ce.ErrInput, "execute: proposal not found", "execute")
	}
	if pp.Status != StatusPending {
		ce.Abort(ce.ErrState, "execute: proposal not pending", "execute")
	}
	bh := sdk.GetEnv().BlockHeight
	if bh < pp.ExecHeight {
		ce.Abort(ce.ErrState, "execute: timelock not elapsed", "execute")
	}
	if bh >= pp.ExpireHeight {
		ce.Abort(ce.ErrState, "execute: proposal expired", "execute")
	}
	// Defense-in-depth: the stored payload must still hash to the committed
	// PayloadHash (a storage tamper between propose and execute is rejected).
	if hashPayload(pp.Payload) != pp.PayloadHash {
		ce.Abort(ce.ErrState, "execute: payload hash mismatch", "execute")
	}
	switch pp.Action {
	case "updateVkey":
		applyUpdateVkey(pp.Payload)
	case "setExpectedElfHash":
		applySetExpectedElfHash(pp.Payload)
	default:
		ce.Abort(ce.ErrState, "execute: unknown action", "execute")
	}
	pp.Status = StatusAccepted
	storeProposal(pp)
	return nil
}

// cancelProposal — owner aborts a pending proposal before execution.
//
//go:wasmexport cancelProposal
func cancelProposal(input *string) *string {
	checkOwner()
	var req struct {
		ProposalId uint64 `json:"proposal_id"`
	}
	if input == nil || json.Unmarshal([]byte(*input), &req) != nil {
		ce.Abort(ce.ErrInput, "cancelProposal: invalid JSON", "cancelProposal")
	}
	pp := loadProposal(req.ProposalId)
	if pp == nil {
		ce.Abort(ce.ErrInput, "cancelProposal: proposal not found", "cancelProposal")
	}
	if pp.Status != StatusPending {
		ce.Abort(ce.ErrState, "cancelProposal: proposal not pending", "cancelProposal")
	}
	pp.Status = StatusCancelled
	storeProposal(pp)
	return nil
}

// expireProposal — anyone may garbage-collect a proposal past its expire
// window (RC cost deters spam). Cannot enact anything; only marks expired.
//
//go:wasmexport expireProposal
func expireProposal(input *string) *string {
	var req struct {
		ProposalId uint64 `json:"proposal_id"`
	}
	if input == nil || json.Unmarshal([]byte(*input), &req) != nil {
		ce.Abort(ce.ErrInput, "expireProposal: invalid JSON", "expireProposal")
	}
	pp := loadProposal(req.ProposalId)
	if pp == nil {
		ce.Abort(ce.ErrInput, "expireProposal: proposal not found", "expireProposal")
	}
	if pp.Status != StatusPending {
		ce.Abort(ce.ErrState, "expireProposal: proposal not pending", "expireProposal")
	}
	if sdk.GetEnv().BlockHeight < pp.ExpireHeight {
		ce.Abort(ce.ErrState, "expireProposal: not yet expired", "expireProposal")
	}
	pp.Status = StatusExpired
	storeProposal(pp)
	return nil
}

// validateActionPayload runs the same shape checks the apply* handlers run,
// at propose() time, so a malformed payload is rejected immediately rather
// than after the 14-day wait.
func validateActionPayload(action, payload string) {
	switch action {
	case "updateVkey":
		var p struct {
			Groth16Vk   string `json:"groth16_vk"`
			VkRoot      string `json:"vk_root"`
			Sp1VkeyHash string `json:"sp1_vkey_hash"`
		}
		if err := json.Unmarshal([]byte(payload), &p); err != nil {
			ce.Abort(ce.ErrJson, "propose(updateVkey): invalid payload JSON", "propose")
			return
		}
		// review6 M10 (adversarial-review correction): propose-side check must
		// match the execute-side atomicity gate added in applyUpdateVkey.
		// Reject a partial proposal at propose() time so it can never queue
		// + waste a 14-day timelock cycle.
		if p.Groth16Vk == "" || p.VkRoot == "" || p.Sp1VkeyHash == "" {
			ce.Abort(ce.ErrInput, "propose(updateVkey) requires all three fields: groth16_vk, vk_root, sp1_vkey_hash (atomic rotation per review6 M10)", "propose")
			return
		}
	case "setExpectedElfHash":
		var p struct {
			Hash string `json:"hash"`
		}
		if err := json.Unmarshal([]byte(payload), &p); err != nil {
			ce.Abort(ce.ErrJson, "propose(setExpectedElfHash): invalid payload JSON", "propose")
		}
		normalizeElfHash(p.Hash) // aborts on bad shape
	}
}
