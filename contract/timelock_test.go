package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"zk-header-verifier/sdk"
)

// The propose/execute timelock is the only way to rotate the vkey or the ELF
// hash after deploy. These tests drive it end to end, and check every status
// change is logged as account-mapping logs its own proposals.

const rotatedVkey = `{"groth16_vk":"a2","vk_root":"b2","sp1_vkey_hash":"c2"}`

func setupTimelock(t *testing.T) {
	t.Helper()
	sdk.ResetTestState()
	sdk.SetTestHaltOnAbort(true)
	for k, v := range map[string]string{KeyGroth16Vk: "aa", KeyVkRoot: "bb", KeySp1VkeyHash: "cc"} {
		sdk.StateSetObject(k, v)
	}
	t.Cleanup(sdk.ResetTestState)
}

// at makes caller the signer (active authority) at block height h.
func at(caller string, h uint64) {
	sdk.SetTestEnvJSON(`{"contract.id":"contract:test","msg.caller":"` + caller + `","msg.sender":"` + caller +
		`","msg.required_auths":["` + caller + `"],"block.height":` + strconv.FormatUint(h, 10) + `}`)
}

func proposeAt(t *testing.T, h uint64, action, payload string) uint64 {
	t.Helper()
	at("hive:owner", h)
	if msg := call(propose, map[string]string{"action": action, "payload": payload}); msg != "" {
		t.Fatalf("propose %s at %d: %s", action, h, msg)
	}
	pp := loadProposal(1)
	for id := uint64(2); loadProposal(id) != nil; id++ {
		pp = loadProposal(id)
	}
	return pp.ProposalId
}

func byID(id uint64) map[string]uint64 { return map[string]uint64{"proposal_id": id} }

func vkey() string {
	return *sdk.StateGetObject(KeyGroth16Vk) + "|" + *sdk.StateGetObject(KeyVkRoot) + "|" + *sdk.StateGetObject(KeySp1VkeyHash)
}

// proposalLogs returns the admin_proposal events logged so far.
func proposalLogs(t *testing.T) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, l := range sdk.TestLogs() {
		rest, ok := strings.CutPrefix(l, "admin_proposal ")
		if !ok {
			continue
		}
		ev := map[string]string{}
		if err := json.Unmarshal([]byte(rest), &ev); err != nil {
			t.Fatalf("admin_proposal log is not JSON: %q", l)
		}
		out = append(out, ev)
	}
	return out
}

func TestTimelock_VkeyRotatesOnlyAfterTheTimelock(t *testing.T) {
	setupTimelock(t)
	id := proposeAt(t, 1000, "updateVkey", rotatedVkey)
	pp := loadProposal(id)
	if pp.ExecHeight != 1000+TimelockLong || pp.ExpireHeight != pp.ExecHeight+ExpireWindowBlocks || pp.Status != StatusPending {
		t.Fatalf("proposal %+v: want exec %d, expire exec+%d, pending", pp, 1000+TimelockLong, ExpireWindowBlocks)
	}
	at("hive:owner", pp.ExecHeight-1)
	if msg := call(execute, byID(id)); !strings.Contains(msg, "timelock not elapsed") {
		t.Fatalf("execute one block early: %q, want timelock not elapsed", msg)
	}
	if vkey() != "aa|bb|cc" {
		t.Fatalf("vkey changed before the timelock: %s", vkey())
	}
	at("hive:owner", pp.ExecHeight)
	if msg := call(execute, byID(id)); msg != "" {
		t.Fatalf("execute at exec height: %s", msg)
	}
	if vkey() != "a2|b2|c2" || loadProposal(id).Status != StatusAccepted {
		t.Fatalf("after execute: vkey %s status %d, want a2|b2|c2 accepted", vkey(), loadProposal(id).Status)
	}
	if msg := call(execute, byID(id)); !strings.Contains(msg, "not pending") {
		t.Fatalf("second execute: %q, want not pending", msg)
	}
}

func TestTimelock_OnlyTheOwnersActiveKeyProposesOrExecutes(t *testing.T) {
	setupTimelock(t)
	at("hive:mallory", 1000)
	if msg := call(propose, map[string]string{"action": "updateVkey", "payload": rotatedVkey}); msg == "" {
		t.Fatal("a non-owner proposed a vkey rotation")
	}
	sdk.SetTestEnvJSON(`{"contract.id":"contract:test","msg.caller":"hive:owner","msg.sender":"hive:owner","msg.required_auths":[],"msg.required_posting_auths":["hive:owner"],"block.height":1000}`)
	if msg := call(propose, map[string]string{"action": "updateVkey", "payload": rotatedVkey}); msg == "" {
		t.Fatal("the owner's posting key proposed a vkey rotation")
	}
	id := proposeAt(t, 1000, "updateVkey", rotatedVkey)
	at("hive:mallory", 1000+TimelockLong)
	if msg := call(execute, byID(id)); msg == "" || vkey() != "aa|bb|cc" {
		t.Fatalf("a non-owner executed the rotation (%q, vkey %s)", msg, vkey())
	}
	if msg := call(cancelProposal, byID(id)); msg == "" || loadProposal(id).Status != StatusPending {
		t.Fatalf("a non-owner cancelled the proposal (%q)", msg)
	}
}

func TestTimelock_CancelledOrExpiredNeverExecutes(t *testing.T) {
	setupTimelock(t)
	cancelled := proposeAt(t, 1000, "updateVkey", rotatedVkey)
	at("hive:owner", 1001)
	if msg := call(cancelProposal, byID(cancelled)); msg != "" {
		t.Fatalf("cancel: %s", msg)
	}
	at("hive:owner", 1000+TimelockLong)
	if msg := call(execute, byID(cancelled)); !strings.Contains(msg, "not pending") || vkey() != "aa|bb|cc" {
		t.Fatalf("executed a cancelled proposal (%q, vkey %s)", msg, vkey())
	}

	stale := proposeAt(t, 2000, "updateVkey", rotatedVkey)
	pp := loadProposal(stale)
	at("hive:anyone", pp.ExpireHeight-1)
	if msg := call(expireProposal, byID(stale)); !strings.Contains(msg, "not yet expired") {
		t.Fatalf("expired early: %q", msg)
	}
	at("hive:owner", pp.ExpireHeight)
	if msg := call(execute, byID(stale)); !strings.Contains(msg, "expired") || vkey() != "aa|bb|cc" {
		t.Fatalf("executed past the expiry (%q, vkey %s)", msg, vkey())
	}
	at("hive:anyone", pp.ExpireHeight)
	if msg := call(expireProposal, byID(stale)); msg != "" || loadProposal(stale).Status != StatusExpired {
		t.Fatalf("anyone expires a stale proposal: %q status %d", msg, loadProposal(stale).Status)
	}
}

// A payload altered in storage after propose no longer matches its hash.
func TestTimelock_ExecuteRunsOnlyTheProposedPayload(t *testing.T) {
	setupTimelock(t)
	id := proposeAt(t, 1000, "updateVkey", rotatedVkey)
	pp := loadProposal(id)
	pp.Payload = `{"groth16_vk":"ee","vk_root":"ee","sp1_vkey_hash":"ee"}`
	storeProposal(pp)
	at("hive:owner", pp.ExecHeight)
	if msg := call(execute, byID(id)); !strings.Contains(msg, "payload hash mismatch") || vkey() != "aa|bb|cc" {
		t.Fatalf("executed a payload that was not proposed (%q, vkey %s)", msg, vkey())
	}
}

func TestTimelock_ElfHashRotatesThroughTheTimelock(t *testing.T) {
	setupTimelock(t)
	sdk.StateSetObject(KeyExpectedElfHash, strings.Repeat("1", 64))
	at("hive:owner", 1000)
	if msg := call(setExpectedElfHash, map[string]string{"hash": strings.Repeat("2", 64)}); !strings.Contains(msg, "already set") {
		t.Fatalf("instant ELF rotation: %q, want already set", msg)
	}
	if msg := call(propose, map[string]string{"action": "setVerifierContract", "payload": "{}"}); !strings.Contains(msg, "unknown or non-timelocked") {
		t.Fatalf("propose an unknown action: %q", msg)
	}
	id := proposeAt(t, 1000, "setExpectedElfHash", `{"hash":"`+strings.Repeat("2", 64)+`"}`)
	at("hive:owner", 1000+TimelockLong)
	if msg := call(execute, byID(id)); msg != "" || *sdk.StateGetObject(KeyExpectedElfHash) != strings.Repeat("2", 64) {
		t.Fatalf("ELF rotation via the timelock: %q, hash %s", msg, *sdk.StateGetObject(KeyExpectedElfHash))
	}
}

// Every status change is logged, so a watcher sees a rotation while its
// timelock still runs.
func TestTimelock_EveryStatusChangeIsLogged(t *testing.T) {
	setupTimelock(t)
	a := proposeAt(t, 1000, "updateVkey", rotatedVkey)
	b := proposeAt(t, 1000, "setExpectedElfHash", `{"hash":"`+strings.Repeat("3", 64)+`"}`)
	c := proposeAt(t, 1000, "updateVkey", rotatedVkey)
	at("hive:owner", 1001)
	call(cancelProposal, byID(b))
	at("hive:owner", 1000+TimelockLong)
	call(execute, byID(a))
	at("hive:anyone", loadProposal(c).ExpireHeight)
	call(expireProposal, byID(c))

	want := []struct {
		id     uint64
		action string
		status uint8
		actor  string
	}{
		{a, "updateVkey", StatusPending, "hive:owner"},
		{b, "setExpectedElfHash", StatusPending, "hive:owner"},
		{c, "updateVkey", StatusPending, "hive:owner"},
		{b, "setExpectedElfHash", StatusCancelled, "hive:owner"},
		{a, "updateVkey", StatusAccepted, "hive:owner"},
		{c, "updateVkey", StatusExpired, "hive:anyone"},
	}
	got := proposalLogs(t)
	if len(got) != len(want) {
		t.Fatalf("%d admin_proposal logs, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		pp := loadProposal(w.id)
		if g["proposalId"] != strconv.FormatUint(w.id, 10) || g["action"] != w.action || g["status"] != strconv.Itoa(int(w.status)) ||
			g["actor"] != w.actor || g["payloadHash"] != "0x"+pp.PayloadHash ||
			g["queueHeight"] != strconv.FormatUint(pp.QueueHeight, 10) || g["execHeight"] != strconv.FormatUint(pp.ExecHeight, 10) {
			t.Fatalf("log %d = %v, want proposal %d %s status %d by %s (hash 0x%s)", i, g, w.id, w.action, w.status, w.actor, pp.PayloadHash)
		}
	}
}
