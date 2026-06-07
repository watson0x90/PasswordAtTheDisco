package auth

import (
	"sync"
	"time"
)

// Limiter is an in-memory failure-rate limiter keyed by an arbitrary string
// (e.g. client IP). A key is locked once it reaches maxFailures within window;
// the lock clears when window elapses since the first counted failure, or on an
// explicit Reset (call on successful auth).
type Limiter struct {
	mu          sync.Mutex
	attempts    map[string]*attempt
	maxFailures int
	window      time.Duration
	now         func() time.Time
}

type attempt struct {
	count int
	first time.Time
}

// NewLimiter returns a Limiter allowing up to maxFailures within window.
func NewLimiter(maxFailures int, window time.Duration) *Limiter {
	return &Limiter{
		attempts:    make(map[string]*attempt),
		maxFailures: maxFailures,
		window:      window,
		now:         time.Now,
	}
}

// Allowed reports whether key may attempt now. If locked, it returns the
// duration until the lock clears.
func (l *Limiter) Allowed(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.attempts[key]
	if !ok {
		return true, 0
	}
	elapsed := l.now().Sub(a.first)
	if elapsed >= l.window {
		delete(l.attempts, key)
		return true, 0
	}
	if a.count >= l.maxFailures {
		return false, l.window - elapsed
	}
	return true, 0
}

// RecordFailure counts a failed attempt for key.
func (l *Limiter) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.attempts[key]
	if !ok || l.now().Sub(a.first) >= l.window {
		l.attempts[key] = &attempt{count: 1, first: l.now()}
		return
	}
	a.count++
}

// Reset clears key's record.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
