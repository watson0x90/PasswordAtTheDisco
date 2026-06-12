package audit

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"
)

// Filter selects audit events. Empty/zero fields match anything.
type Filter struct {
	Text   string    // case-insensitive substring across actor/role/action/target/source/result
	Action string    // exact action (e.g. "reveal_secret")
	Result string    // exact result (e.g. "denied")
	Actor  string    // exact actor (operator username)
	From   time.Time // inclusive lower time bound
	To     time.Time // exclusive upper time bound
	Limit  int       // max events returned by Query, newest first (default 200, hard cap 1000)
}

func (f Filter) matches(e Event, lowerText string) bool {
	if f.Action != "" && e.Action != f.Action {
		return false
	}
	if f.Result != "" && e.Result != f.Result {
		return false
	}
	if f.Actor != "" && e.Actor != f.Actor {
		return false
	}
	if !f.From.IsZero() && e.Time.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !e.Time.Before(f.To) {
		return false
	}
	if lowerText != "" && !matchText(e, lowerText) {
		return false
	}
	return true
}

func scanner(file *os.File) *bufio.Scanner {
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	return sc
}

// Query reads the JSON-lines audit log at path and returns the most recent events
// matching f, newest first. Memory is bounded to the limit (a circular buffer), so
// it is safe on a large log. A missing file yields no events (not an error).
func Query(path string, f Filter) ([]Event, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	text := strings.ToLower(f.Text)

	ring := make([]Event, limit)
	n := 0 // total matches seen
	sc := scanner(file)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil || !f.matches(e, text) {
			continue
		}
		ring[n%limit] = e
		n++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	count := n
	if count > limit {
		count = limit
	}
	out := make([]Event, count)
	for i := 0; i < count; i++ {
		out[i] = ring[(n-1-i)%limit] // newest first
	}
	return out, nil
}

// StreamCSV writes all events matching f (no limit, chronological order) as CSV to
// w. Streamed, so memory stays flat regardless of log size.
func StreamCSV(path string, f Filter, w io.Writer) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "actor", "role", "action", "target", "source", "result"})
	if path == "" {
		cw.Flush()
		return cw.Error()
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			cw.Flush()
			return cw.Error()
		}
		return err
	}
	defer file.Close()

	text := strings.ToLower(f.Text)
	sc := scanner(file)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil || !f.matches(e, text) {
			continue
		}
		if err := cw.Write([]string{
			e.Time.UTC().Format(time.RFC3339), e.Actor, e.Role, e.Action, e.Target, e.Source, e.Result,
		}); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

func matchText(e Event, lower string) bool {
	return strings.Contains(strings.ToLower(e.Actor), lower) ||
		strings.Contains(strings.ToLower(e.Role), lower) ||
		strings.Contains(strings.ToLower(e.Action), lower) ||
		strings.Contains(strings.ToLower(e.Target), lower) ||
		strings.Contains(strings.ToLower(e.Source), lower) ||
		strings.Contains(strings.ToLower(e.Result), lower)
}
