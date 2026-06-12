package auth

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Lockout defaults: after this many failed logins within the window, an account is
// locked for the duration. In-memory (ephemeral, like the per-IP limiter); the
// durable record of attempts is the audit log, from which last-login is re-seeded
// on startup.
const (
	DefaultLockoutThreshold = 5
	DefaultLockoutWindow    = 15 * time.Minute
	DefaultLockoutDuration  = 15 * time.Minute
	maxRecentAttempts       = 50
)

// Attempt is one recorded login attempt.
type Attempt struct {
	Time     time.Time `json:"time"`
	Username string    `json:"username"`
	Source   string    `json:"source"`
	Result   string    `json:"result"` // "ok" | "denied" | "locked"
}

// LoginState is the per-operator login summary.
type LoginState struct {
	FailedAttempts int
	Locked         bool
	LockedUntil    time.Time
	LastSuccess    time.Time
	LastSuccessIP  string
	LastFailure    time.Time
}

type userLogin struct {
	failed        int
	windowStart   time.Time
	lockedUntil   time.Time
	lastSuccess   time.Time
	lastSuccessIP string
	lastFailure   time.Time
	touched       time.Time // last activity, for LRU eviction
}

// maxTrackedUsers caps the per-username map. handleLogin records a failure for ANY
// attempted username (pre-auth, attacker-controlled), so without a bound a dictionary
// spray would accrete unbounded entries. Lockout state is ephemeral, so evicting the
// least-recently-active entry is safe.
const maxTrackedUsers = 10000

// LoginTracker tracks per-operator failed-login counts + lockouts plus a bounded
// recent-activity ring. Safe for concurrent use.
type LoginTracker struct {
	mu        sync.Mutex
	now       func() time.Time
	threshold int
	window    time.Duration
	lockFor   time.Duration
	users     map[string]*userLogin
	recent    []Attempt // oldest..newest, bounded to maxRecentAttempts
}

// NewLoginTracker builds a tracker. Non-positive params fall back to the defaults.
func NewLoginTracker(threshold int, window, lockFor time.Duration) *LoginTracker {
	if threshold <= 0 {
		threshold = DefaultLockoutThreshold
	}
	if window <= 0 {
		window = DefaultLockoutWindow
	}
	if lockFor <= 0 {
		lockFor = DefaultLockoutDuration
	}
	return &LoginTracker{
		now:       time.Now,
		threshold: threshold,
		window:    window,
		lockFor:   lockFor,
		users:     map[string]*userLogin{},
	}
}

// evictOldestLocked removes the least-recently-touched entry (called when at cap).
func (t *LoginTracker) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, v := range t.users {
		if first || v.touched.Before(oldest) {
			oldest, oldestKey, first = v.touched, k, false
		}
	}
	if oldestKey != "" {
		delete(t.users, oldestKey)
	}
}

func (t *LoginTracker) userForLocked(username string) *userLogin {
	u := t.users[username]
	if u == nil {
		if len(t.users) >= maxTrackedUsers {
			t.evictOldestLocked()
		}
		u = &userLogin{}
		t.users[username] = u
	}
	return u
}

// Locked reports whether username is currently locked out and until when.
func (t *LoginTracker) Locked(username string) (bool, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	u := t.users[username]
	if u != nil && u.lockedUntil.After(t.now()) {
		return true, u.lockedUntil
	}
	return false, time.Time{}
}

// RecordSuccess clears failure state and records the successful login.
func (t *LoginTracker) RecordSuccess(username, source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	u := t.userForLocked(username)
	u.touched = now
	u.failed = 0
	u.windowStart = time.Time{}
	u.lockedUntil = time.Time{}
	u.lastSuccess = now
	u.lastSuccessIP = source
	t.pushLocked(Attempt{Time: now, Username: username, Source: source, Result: "ok"})
}

// RecordFailure increments the failure count (resetting the window if it lapsed)
// and locks the account once the threshold is reached.
func (t *LoginTracker) RecordFailure(username, source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	u := t.userForLocked(username)
	u.touched = now
	if !u.windowStart.IsZero() && now.Sub(u.windowStart) > t.window {
		u.failed = 0
		u.windowStart = time.Time{}
	}
	if u.failed == 0 {
		u.windowStart = now
	}
	u.failed++
	u.lastFailure = now
	if u.failed >= t.threshold {
		u.lockedUntil = now.Add(t.lockFor)
	}
	t.pushLocked(Attempt{Time: now, Username: username, Source: source, Result: "denied"})
}

// RecordBlocked records an attempt rejected because the account was locked.
func (t *LoginTracker) RecordBlocked(username, source string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pushLocked(Attempt{Time: t.now(), Username: username, Source: source, Result: "locked"})
}

// Unlock clears a lockout + failure count (a lead action).
func (t *LoginTracker) Unlock(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if u := t.users[username]; u != nil {
		u.failed = 0
		u.windowStart = time.Time{}
		u.lockedUntil = time.Time{}
	}
}

// State returns the per-operator login summary.
func (t *LoginTracker) State(username string) LoginState {
	t.mu.Lock()
	defer t.mu.Unlock()
	u := t.users[username]
	if u == nil {
		return LoginState{}
	}
	locked := u.lockedUntil.After(t.now())
	st := LoginState{
		FailedAttempts: u.failed,
		Locked:         locked,
		LastSuccess:    u.lastSuccess,
		LastSuccessIP:  u.lastSuccessIP,
		LastFailure:    u.lastFailure,
	}
	if locked {
		st.LockedUntil = u.lockedUntil
	}
	return st
}

// Recent returns up to n most-recent attempts, newest first.
func (t *LoginTracker) Recent(n int) []Attempt {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n <= 0 || n > len(t.recent) {
		n = len(t.recent)
	}
	out := make([]Attempt, n)
	for i := 0; i < n; i++ {
		out[i] = t.recent[len(t.recent)-1-i]
	}
	return out
}

func (t *LoginTracker) pushLocked(a Attempt) {
	t.recent = append(t.recent, a)
	if len(t.recent) > maxRecentAttempts {
		t.recent = t.recent[len(t.recent)-maxRecentAttempts:]
	}
}

// SeedFromAudit best-effort seeds last-login times + recent activity from the
// durable audit log (login events), so they survive a restart. Lockout counters are
// intentionally NOT restored (they are ephemeral, like the per-IP limiter).
func (t *LoginTracker) SeedFromAudit(path string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	t.mu.Lock()
	defer t.mu.Unlock()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e struct {
			Time   time.Time `json:"time"`
			Actor  string    `json:"actor"`
			Action string    `json:"action"`
			Result string    `json:"result"`
			Source string    `json:"source"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Action != "login" || e.Actor == "" {
			continue
		}
		switch e.Result {
		case "ok":
			u := t.userForLocked(e.Actor)
			u.touched = e.Time
			u.lastSuccess = e.Time
			u.lastSuccessIP = e.Source
			t.pushLocked(Attempt{Time: e.Time, Username: e.Actor, Source: e.Source, Result: "ok"})
		case "denied":
			u := t.userForLocked(e.Actor)
			u.touched = e.Time
			u.lastFailure = e.Time
			t.pushLocked(Attempt{Time: e.Time, Username: e.Actor, Source: e.Source, Result: "denied"})
		}
	}
}
