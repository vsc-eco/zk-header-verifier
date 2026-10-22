//go:build !gc.custom

package sdk

// This file is the non-wasm (!gc.custom) build, used only by `go test`; the
// contract itself uses runtime_imports.go. The host imports are backed by an
// in-memory store, a settable env, a real keccak256 and a settable
// sp1_verify_groth16 verdict, so tests can run the handlers; aborts/reverts
// return unless SetTestHaltOnAbort (see the helpers at the end of the file).

import (
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

//go:wasmimport sdk console.log
func log(s *string) *string { return nil }

func Log(s string) {
	log(&s)
}

//go:wasmimport sdk db.set_object
func stateSetObject(key *string, value *string) *string { testState[*key] = *value; return nil }

//go:wasmimport sdk db.get_object
func stateGetObject(key *string) *string {
	if v, ok := testState[*key]; ok {
		return &v
	}
	return nil
}

//go:wasmimport sdk db.rm_object
func stateDeleteObject(key *string) *string { delete(testState, *key); return nil }

//go:wasmimport sdk ephem_db.set_object
func ephemStateSetObject(key *string, value *string) *string { return nil }

//go:wasmimport sdk ephem_db.get_object
func ephemStateGetObject(contractId *string, key *string) *string { return nil }

//go:wasmimport sdk ephem_db.rm_object
func ephemStateDeleteObject(key *string) *string { return nil }

//go:wasmimport sdk system.get_env
func getEnv(arg *string) *string { return &testEnvJSON }

//go:wasmimport sdk system.get_env_key
func getEnvKey(arg *string) *string {
	if v, ok := testEnvKeys[*arg]; ok {
		return &v
	}
	return nil
}

//go:wasmimport sdk system.verify_address
func verifyAddress(arg *string) *string { return nil }

//go:wasmimport sdk hive.get_balance
func getBalance(arg1 *string, arg2 *string) *string { return nil }

//go:wasmimport sdk hive.draw
func hiveDraw(arg1 *string, arg2 *string) *string { return nil }

//go:wasmimport sdk hive.draw_from
func hiveDrawFrom(arg1 *string, arg2 *string, arg3 *string) *string { return nil }

//go:wasmimport sdk hive.transfer
func hiveTransfer(arg1 *string, arg2 *string, arg3 *string) *string { return nil }

//go:wasmimport sdk hive.withdraw
func hiveWithdraw(arg1 *string, arg2 *string, arg3 *string) *string { return nil }

//go:wasmimport sdk contracts.read
func contractRead(contractId *string, key *string) *string { return nil }

//go:wasmimport sdk contracts.call
func contractCall(contractId *string, method *string, payload *string, options *string) *string {
	return nil
}

//go:wasmimport sdk tss_v2.create_key
func tssCreateKey(keyId *string, algo *string, epochs *string) *string { return nil }

//go:wasmimport sdk tss_v2.renew_key
func tssRenewKey(keyId *string, epochs *string) *string { return nil }

//go:wasmimport sdk tss.sign_key
func tssSignKey(keyId *string, msgId *string) *string { return nil }

//go:wasmimport sdk tss.get_key
func tssGetKey(keyId *string) *string { return nil }

// var envMap = []string{
// 	"contract.id",
// 	"tx.origin",
// 	"tx.id",
// 	"tx.index",
// 	"tx.op_index",
// 	"block.id",
// 	"block.height",
// 	"block.timestamp",
// }

//go:wasmimport sdk crypto.keccak256
func keccak256(data *string) *string {
	b, err := hex.DecodeString(*data)
	if err != nil {
		return nil
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	out := hex.EncodeToString(h.Sum(nil))
	return &out
}

//go:wasmimport sdk crypto.sp1_verify_groth16
func sp1VerifyGroth16(proof *string, publicInputs *string, sp1VkeyHash *string, groth16Vk *string, vkRoot *string) *string {
	v := "false"
	if testSp1Verdict {
		v = "true"
	}
	return &v
}

//go:wasmimport env abort
func abort(msg, file *string, line, column *int32) {
	if !testHaltOnAbort {
		return
	}
	if msg != nil {
		panic(*msg)
	}
	panic("abort")
}

//go:wasmimport env revert
func revert(msg, symbol *string) {
	if !testHaltOnAbort {
		return
	}
	m := ""
	if msg != nil {
		m = *msg
	}
	if symbol != nil && *symbol != "" {
		m = *symbol + ": " + m
	}
	panic(m)
}

// ---- test helpers (non-wasm build only) ----

var (
	testState       = map[string]string{}
	testEnvKeys     = map[string]string{}
	testEnvJSON     = `{"contract.id":"contract:test","msg.caller":"hive:owner","msg.sender":"hive:owner","msg.required_auths":["hive:owner"]}`
	testSp1Verdict  = false
	testHaltOnAbort = false
)

// ResetTestState clears the store and env and makes every proof fail to verify.
func ResetTestState() {
	testState = map[string]string{}
	testEnvKeys = map[string]string{"contract.owner": "hive:owner"}
	testEnvJSON = `{"contract.id":"contract:test","msg.caller":"hive:owner","msg.sender":"hive:owner","msg.required_auths":["hive:owner"]}`
	testSp1Verdict = false
	testHaltOnAbort = false
}

// SetTestCaller makes addr the caller and sender (active authority).
func SetTestCaller(addr string) {
	testEnvJSON = `{"contract.id":"contract:test","msg.caller":"` + addr + `","msg.sender":"` + addr + `","msg.required_auths":["` + addr + `"]}`
}

// SetTestEnvJSON replaces the whole env (e.g. a posting-only signer).
func SetTestEnvJSON(env string) { testEnvJSON = env }

// SetTestHaltOnAbort makes abort/revert panic, as the runtime halts the call.
// Off by default: the review6 tests check the post-abort zero returns a
// runtime that did not halt would see.
func SetTestHaltOnAbort(on bool) { testHaltOnAbort = on }

// SetTestSp1Verdict sets what sp1_verify_groth16 answers (the pairing check is
// the node's; contract tests drive everything after it).
func SetTestSp1Verdict(ok bool) { testSp1Verdict = ok }
