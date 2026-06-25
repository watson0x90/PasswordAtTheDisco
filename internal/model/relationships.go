package model

import "sort"

// PeerRef is an identity-only reference to an account in a relationship list.
// It deliberately carries NO secret material (no NT hash, no password).
type PeerRef struct {
	Username      string `json:"username"`
	Domain        string `json:"domain"`
	RiskLevel     string `json:"risk_level"`
	Cracked       bool   `json:"cracked"`
	Enabled       bool   `json:"enabled"`
	HasDAPath     bool   `json:"has_da_path"`    // flags the DA account(s) behind a Shared-DA escalation
	ControlsTier0 bool   `json:"controls_tier0"` // controls a Tier-0 / DA-equivalent asset (BloodHound)
}

// ReuseGroupPeers returns the OTHER accounts sharing focus's NT hash (exact password
// reuse). Accounts with an empty/blank-password NT hash (reuseKey == "") never group.
// Peers are sorted DA-first then by descending risk, and capped at limit (limit <= 0
// means no cap). total/crackedCount/daCount are EXACT (counted before the cap) so a
// caller can show "79 share this password" while listing only the top `limit`. The
// returned slice is always non-nil (so JSON renders [] not null).
func ReuseGroupPeers(accts []Account, focus Account, limit int) (peers []PeerRef, total, crackedCount, daCount int) {
	peers = []PeerRef{}
	key := reuseKey(focus.NTHash)
	if key == "" {
		return peers, 0, 0, 0
	}
	all := []PeerRef{}
	for _, a := range accts {
		if a.Username == focus.Username && a.Domain == focus.Domain {
			continue // exclude self
		}
		if reuseKey(a.NTHash) != key {
			continue
		}
		total++
		if a.Cracked {
			crackedCount++
		}
		da := a.HasDAPathway()
		if da {
			daCount++
		}
		all = append(all, PeerRef{
			Username:      a.Username,
			Domain:        a.Domain,
			RiskLevel:     a.RiskLevel,
			Cracked:       a.Cracked,
			Enabled:       a.Enabled,
			HasDAPath:     da,
			ControlsTier0: a.ControlsTier0,
		})
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].HasDAPath != all[j].HasDAPath {
			return all[i].HasDAPath // DA first
		}
		return levelRank(all[i].RiskLevel) > levelRank(all[j].RiskLevel)
	})
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	peers = all
	return peers, total, crackedCount, daCount
}
