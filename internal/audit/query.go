package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

// Filter selects audit events. Empty fields match anything.
type Filter struct {
	Text   string // case-insensitive substring across actor/role/action/target/source/result
	Action string // exact action (e.g. "reveal_secret")
	Result string // exact result (e.g. "denied")
	Actor  string // exact actor (operator username)
	Limit  int    // max events returned, newest first (default 200, hard cap 1000)
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
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if f.Action != "" && e.Action != f.Action {
			continue
		}
		if f.Result != "" && e.Result != f.Result {
			continue
		}
		if f.Actor != "" && e.Actor != f.Actor {
			continue
		}
		if text != "" && !matchText(e, text) {
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

func matchText(e Event, lower string) bool {
	return strings.Contains(strings.ToLower(e.Actor), lower) ||
		strings.Contains(strings.ToLower(e.Role), lower) ||
		strings.Contains(strings.ToLower(e.Action), lower) ||
		strings.Contains(strings.ToLower(e.Target), lower) ||
		strings.Contains(strings.ToLower(e.Source), lower) ||
		strings.Contains(strings.ToLower(e.Result), lower)
}
