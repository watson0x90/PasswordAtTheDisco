package auth

import (
	"testing"
	"time"
)

func TestLockoutAfterThreshold(t *testing.T) {
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tr := NewLoginTracker(3, 10*time.Minute, 15*time.Minute)
	tr.now = func() time.Time { return clock }

	for i := 0; i < 2; i++ {
		tr.RecordFailure("ana", "10.0.0.1")
	}
	if locked, _ := tr.Locked("ana"); locked {
		t.Fatal("should not be locked before reaching the threshold")
	}
	tr.RecordFailure("ana", "10.0.0.1") // 3rd -> lock
	locked, until := tr.Locked("ana")
	if !locked {
		t.Fatal("should be locked at the threshold")
	}
	if !until.Equal(clock.Add(15 * time.Minute)) {
		t.Fatalf("locked_until = %v, want +15m", until)
	}

	// after the lockout expires, it unlocks
	clock = clock.Add(16 * time.Minute)
	if locked, _ := tr.Locked("ana"); locked {
		t.Fatal("should auto-unlock after the lockout duration")
	}
}

func TestLockoutWindowResets(t *testing.T) {
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tr := NewLoginTracker(3, 10*time.Minute, 15*time.Minute)
	tr.now = func() time.Time { return clock }

	tr.RecordFailure("ana", "ip") // 1
	tr.RecordFailure("ana", "ip") // 2
	clock = clock.Add(11 * time.Minute)
	tr.RecordFailure("ana", "ip") // window lapsed -> counts as 1
	if locked, _ := tr.Locked("ana"); locked {
		t.Fatal("failures outside the window must not accumulate into a lockout")
	}
	if st := tr.State("ana"); st.FailedAttempts != 1 {
		t.Fatalf("failed count = %d, want 1 (window reset)", st.FailedAttempts)
	}
}

func TestSuccessAndUnlockClearState(t *testing.T) {
	tr := NewLoginTracker(2, time.Minute, time.Hour)
	tr.RecordFailure("ana", "ip")
	tr.RecordFailure("ana", "ip") // locked
	if locked, _ := tr.Locked("ana"); !locked {
		t.Fatal("expected locked")
	}
	tr.Unlock("ana")
	if locked, _ := tr.Locked("ana"); locked {
		t.Fatal("Unlock should clear the lockout")
	}

	tr.RecordSuccess("boss", "ip")
	st := tr.State("boss")
	if st.LastSuccess.IsZero() || st.FailedAttempts != 0 {
		t.Fatalf("success state = %+v", st)
	}
	// recent is newest-first and bounded
	if r := tr.Recent(10); len(r) == 0 || r[0].Username != "boss" || r[0].Result != "ok" {
		t.Fatalf("recent[0] = %+v", r)
	}
}
