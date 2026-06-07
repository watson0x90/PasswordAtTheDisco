package auth

import (
	"testing"
	"time"
)

func TestLimiterLocksAfterMaxFailures(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(3, time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allowed("1.2.3.4"); !ok {
			t.Fatalf("blocked too early at attempt %d", i)
		}
		l.RecordFailure("1.2.3.4")
	}
	ok, retry := l.Allowed("1.2.3.4")
	if ok {
		t.Fatal("should be locked after 3 failures")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry-after, got %v", retry)
	}
	if ok, _ := l.Allowed("5.6.7.8"); !ok {
		t.Fatal("an unrelated key should not be locked")
	}
}

func TestLimiterResetClears(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	l.RecordFailure("k")
	l.RecordFailure("k")
	if ok, _ := l.Allowed("k"); ok {
		t.Fatal("expected lock after 2 failures")
	}
	l.Reset("k")
	if ok, _ := l.Allowed("k"); !ok {
		t.Fatal("Reset should clear the lock")
	}
}

func TestLimiterWindowExpires(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(2, time.Minute)
	l.now = func() time.Time { return now }
	l.RecordFailure("k")
	l.RecordFailure("k")
	if ok, _ := l.Allowed("k"); ok {
		t.Fatal("expected lock")
	}
	now = now.Add(61 * time.Second)
	if ok, _ := l.Allowed("k"); !ok {
		t.Fatal("lock should clear once the window elapses")
	}
}
