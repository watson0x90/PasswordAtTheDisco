// Package audit writes structured, append-only audit events. Events record that
// an action happened (who/what/when) -- they NEVER contain credential cleartext.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event is a single audit record.
type Event struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`            // operator username
	Role   string    `json:"role,omitempty"`   // operator role
	Action string    `json:"action"`           // e.g. "login", "reveal_secret"
	Target string    `json:"target,omitempty"` // e.g. account username (NOT its password)
	Source string    `json:"source,omitempty"` // remote address
	Result string    `json:"result"`           // "ok" | "denied" | "error"
}

// Logger writes audit events as JSON lines to an io.Writer.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// New returns a Logger writing to w.
func New(w io.Writer) *Logger { return &Logger{w: w} }

// Log writes an event (timestamped if not already).
func (l *Logger) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}
