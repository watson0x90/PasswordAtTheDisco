// Package secretsdump parses cracked/uncracked credential dumps into structured
// accounts. It accepts the impacket secretsdump NTDS format
// (username:rid:lm:nt:::password) and a simple username:hash[:password] format.
//
// Ported from legacy-python/core/data.py. One deliberate deviation: the Python
// $HEX[] decoder used chardet to guess the byte encoding; this implementation
// decodes as UTF-8 and falls back to Latin-1 (lossless, byte->rune) rather than
// pulling in an unvetted charset-detection dependency.
package secretsdump

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ParsedAccount is one account parsed from a dump file.
type ParsedAccount struct {
	Username string
	Domain   string
	Hash     string // NTLM hash (field index 3 in secretsdump format)
	Password string // cleartext; non-empty only for cracked accounts
	Cracked  bool
}

// ParseCracked parses cracked-password lines for domain. Per line:
//   - secretsdump (>=7 fields): username:rid:lm:nt[:...empty]:password
//   - simple (3 fields):        username:hash:password
//
// Passwords are $HEX[]-decoded. A secretsdump line with an empty password, or
// any line with an unrecognized field count, is skipped.
func ParseCracked(r io.Reader, domain string) ([]ParsedAccount, error) {
	var out []ParsedAccount
	sc := newScanner(r)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		switch {
		case len(parts) >= 7:
			pw := joinPassword(parts)
			if pw == "" {
				continue
			}
			out = append(out, ParsedAccount{
				Username: parts[0], Domain: domain, Hash: parts[3],
				Password: decodeHex(pw), Cracked: true,
			})
		case len(parts) == 3:
			out = append(out, ParsedAccount{
				Username: parts[0], Domain: domain, Hash: parts[1],
				Password: decodeHex(parts[2]), Cracked: true,
			})
		}
	}
	return out, sc.Err()
}

// ParseUncracked parses uncracked (hash-only) lines for domain. Per line:
//   - secretsdump (>=7 fields): username:rid:lm:nt:::
//   - simple (2 fields):        username:hash
func ParseUncracked(r io.Reader, domain string) ([]ParsedAccount, error) {
	var out []ParsedAccount
	sc := newScanner(r)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		switch {
		case len(parts) >= 7:
			out = append(out, ParsedAccount{Username: parts[0], Domain: domain, Hash: parts[3]})
		case len(parts) == 2:
			out = append(out, ParsedAccount{Username: parts[0], Domain: domain, Hash: parts[1]})
		}
	}
	return out, sc.Err()
}

// ParseDomain parses the cracked and uncracked files for a domain.
func ParseDomain(domain, crackedPath, uncrackedPath string) (cracked, uncracked []ParsedAccount, err error) {
	if cracked, err = parseFile(crackedPath, domain, ParseCracked); err != nil {
		return nil, nil, err
	}
	if uncracked, err = parseFile(uncrackedPath, domain, ParseUncracked); err != nil {
		return nil, nil, err
	}
	return cracked, uncracked, nil
}

func parseFile(path, domain string, fn func(io.Reader, string) ([]ParsedAccount, error)) ([]ParsedAccount, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return fn(f, domain)
}

// joinPassword returns the password from a secretsdump line: everything after
// the run of empty placeholder fields following the NTLM hash, rejoined with ':'
// so passwords containing colons survive.
func joinPassword(parts []string) string {
	idx := 4
	for idx < len(parts) && parts[idx] == "" {
		idx++
	}
	return strings.Join(parts[idx:], ":")
}

// decodeHex decodes hashcat $HEX[...] segments. Mirrors data.py: it only acts
// when "$HEX" is present, splits on '$', and concatenates the decoded/literal
// segments (so literal '$' separators are not preserved -- matching the Python).
func decodeHex(password string) string {
	if !strings.Contains(password, "$HEX") {
		return password
	}
	var b strings.Builder
	for _, seg := range strings.Split(password, "$") {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "HEX[") {
			if end := strings.Index(seg, "]"); end > 4 {
				if raw, err := hex.DecodeString(seg[4:end]); err == nil {
					b.WriteString(decodeBytes(raw))
					continue
				}
			}
		}
		b.WriteString(seg)
	}
	return b.String()
}

// decodeBytes decodes raw bytes as UTF-8, falling back to a lossless Latin-1
// mapping (each byte -> the rune of the same value) when not valid UTF-8.
func decodeBytes(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(decodeText(r))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long lines
	return sc
}

// decodeText normalizes dump bytes to a UTF-8 reader: it strips a UTF-8 BOM and
// transcodes UTF-16 (LE/BE, by BOM) using only stdlib. Windows tools (PowerShell
// Out-File/redirection) default to UTF-16LE+BOM, which would otherwise split into
// NUL garbage on ':'. On any read error the original reader is returned unchanged.
func decodeText(r io.Reader) io.Reader {
	b, err := io.ReadAll(r)
	if err != nil {
		return r
	}
	switch {
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF: // UTF-8 BOM
		return bytes.NewReader(b[3:])
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE: // UTF-16 LE
		return bytes.NewReader(utf16ToUTF8(b[2:], false))
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF: // UTF-16 BE
		return bytes.NewReader(utf16ToUTF8(b[2:], true))
	default:
		return bytes.NewReader(b)
	}
}

func utf16ToUTF8(b []byte, bigEndian bool) []byte {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			u = append(u, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return []byte(string(utf16.Decode(u)))
}
