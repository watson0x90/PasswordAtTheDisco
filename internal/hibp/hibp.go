// Package hibp looks up NTLM hashes against a local Have I Been Pwned NTLM
// dump using a prefix index, and computes NTLM hashes from plaintext.
//
// Ported from legacy-python/core/hibp_correlation.py. The dump is a file of
// sorted "HASH:COUNT" lines; a sibling "<file>.index<N>" maps each N-char hex
// prefix to the byte offset where that prefix's block begins. A lookup binary-
// searches the index for the prefix, then scans only that block.
package hibp

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// DefaultPrefixLen is the hex-prefix length used by the standard index (.index5).
const DefaultPrefixLen = 5

// NTLMHash returns the uppercase-hex NTLM hash of password: MD4 of the password
// encoded as UTF-16LE.
func NTLMHash(password string) string {
	units := utf16.Encode([]rune(password))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	h := md4.New()
	_, _ = h.Write(buf)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

type entry struct {
	prefix string
	offset int64
}

// Searcher answers NTLM-hash membership/breach-count queries against the dump.
// It is safe for concurrent use after Open.
type Searcher struct {
	f         *os.File
	size      int64
	prefixLen int
	entries   []entry // sorted by prefix
}

// Open loads the prefix index ("<hashFile>.index<prefixLen>") and opens the
// hash file for lookups. Close it when done.
func Open(hashFile string, prefixLen int) (*Searcher, error) {
	entries, err := loadIndex(fmt.Sprintf("%s.index%d", hashFile, prefixLen))
	if err != nil {
		return nil, err
	}
	f, err := os.Open(hashFile)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Searcher{f: f, size: fi.Size(), prefixLen: prefixLen, entries: entries}, nil
}

// Close releases the underlying file handle.
func (s *Searcher) Close() error { return s.f.Close() }

func loadIndex(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		off, err := strconv.ParseInt(line[i+1:], 10, 64)
		if err != nil {
			continue
		}
		entries = append(entries, entry{prefix: line[:i], offset: off})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].prefix < entries[j].prefix })
	return entries, nil
}

// LookupHash reports whether the 32-hex NTLM hash is present in the dump and its
// breach count. An invalid-length hash or empty index yields (false, 0, nil).
func (s *Searcher) LookupHash(ntlm string) (found bool, count int, err error) {
	ntlm = strings.ToUpper(strings.TrimSpace(ntlm))
	if len(ntlm) != 32 || len(s.entries) == 0 {
		return false, 0, nil
	}
	prefix := ntlm[:s.prefixLen]
	i := sort.Search(len(s.entries), func(k int) bool { return s.entries[k].prefix >= prefix })
	if i >= len(s.entries) || s.entries[i].prefix != prefix {
		return false, 0, nil
	}
	start := s.entries[i].offset
	end := s.size
	if i+1 < len(s.entries) {
		end = s.entries[i+1].offset
	}
	if start >= end {
		return false, 0, nil
	}

	br := bufio.NewReader(io.NewSectionReader(s.f, start, end-start))
	for {
		line, rerr := br.ReadString('\n')
		if h, c, ok := parseHashLine(line); ok {
			if h == ntlm {
				return true, c, nil
			}
			if h > ntlm {
				return false, 0, nil // sorted block: passed where it would be
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return false, 0, nil
			}
			return false, 0, rerr
		}
	}
}

// LookupPassword hashes password to NTLM and looks it up.
func (s *Searcher) LookupPassword(password string) (bool, int, error) {
	return s.LookupHash(NTLMHash(password))
}

func parseHashLine(line string) (hash string, count int, ok bool) {
	line = strings.TrimRight(line, "\r\n")
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", 0, false
	}
	c, err := strconv.Atoi(strings.TrimSpace(line[i+1:]))
	if err != nil {
		return "", 0, false
	}
	return strings.ToUpper(line[:i]), c, true
}

// CategorizeRisk maps a breach count to a risk label.
func CategorizeRisk(breachCount int) string {
	switch {
	case breachCount == 0:
		return "None"
	case breachCount < 10:
		return "Low"
	case breachCount < 100:
		return "Medium"
	case breachCount < 1000:
		return "High"
	case breachCount < 10000:
		return "Very High"
	default:
		return "Extreme"
	}
}

// Factor maps a breach count to an environmental risk multiplier (1.0–1.5).
func Factor(breachCount int) float64 {
	switch {
	case breachCount == 0:
		return 1.0
	case breachCount < 100:
		return 1.1
	case breachCount < 1000:
		return 1.2
	case breachCount < 10000:
		return 1.3
	case breachCount < 100000:
		return 1.4
	default:
		return 1.5
	}
}
