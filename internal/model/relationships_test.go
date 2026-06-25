package model

import "testing"

func acct(u, d, hash, risk, da string, cracked, enabled bool) Account {
	return Account{Username: u, Domain: d, NTHash: hash, RiskLevel: risk, DADomains: da, Cracked: cracked, Enabled: enabled}
}

func TestReuseGroupPeers_GroupsSortsAndCounts(t *testing.T) {
	focus := acct("alice", "CORP", "AAA", "Critical", "", true, true)
	accts := []Account{
		focus,
		acct("bob", "CORP", "AAA", "High", "", true, true),
		acct("administrator", "CORP", "AAA", "Critical", "CORP", true, true), // DA peer
		acct("carol", "CORP", "BBB", "Low", "", true, true),                  // different hash
	}
	peers, total, cracked, da := ReuseGroupPeers(accts, focus, 100)
	if total != 2 || cracked != 2 || da != 1 {
		t.Fatalf("totals: got total=%d cracked=%d da=%d, want 2/2/1", total, cracked, da)
	}
	if len(peers) != 2 {
		t.Fatalf("peers: got %d, want 2", len(peers))
	}
	if peers[0].Username != "administrator" || !peers[0].HasDAPath {
		t.Errorf("DA peer must sort first with HasDAPath=true, got %+v", peers[0])
	}
	for _, p := range peers {
		if p.Username == "alice" || p.Username == "carol" {
			t.Errorf("unexpected peer %s (self or different-hash)", p.Username)
		}
	}
}

func TestReuseGroupPeers_BlankHashNeverGroups(t *testing.T) {
	focus := acct("svc", "CORP", "", "Low", "", false, true)
	accts := []Account{focus, acct("svc2", "CORP", "", "Low", "", false, true)}
	peers, total, _, _ := ReuseGroupPeers(accts, focus, 100)
	if total != 0 || len(peers) != 0 {
		t.Fatalf("blank hash must not group: total=%d peers=%d", total, len(peers))
	}
	if peers == nil {
		t.Errorf("peers must be non-nil empty slice for stable JSON []")
	}
}

func TestReuseGroupPeers_CapTruncatesButCountsStayExact(t *testing.T) {
	focus := acct("a0", "CORP", "AAA", "Low", "", true, true)
	accts := []Account{focus}
	for i := 1; i <= 5; i++ {
		accts = append(accts, acct("a"+string(rune('0'+i)), "CORP", "AAA", "Low", "", true, true))
	}
	peers, total, cracked, _ := ReuseGroupPeers(accts, focus, 2)
	if len(peers) != 2 {
		t.Fatalf("cap: got %d peers, want 2", len(peers))
	}
	if total != 5 || cracked != 5 {
		t.Fatalf("counts must be exact pre-cap: total=%d cracked=%d, want 5/5", total, cracked)
	}
}
