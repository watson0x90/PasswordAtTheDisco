package hibp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/watson0x90/PasswordAtTheDisco/internal/fsutil"
)

// IndexPath returns the sibling index path for a dump ("<hashFile>.index<prefixLen>").
func IndexPath(hashFile string, prefixLen int) string {
	return fmt.Sprintf("%s.index%d", hashFile, prefixLen)
}

// BuildIndex scans a sorted HIBP NTLM dump and writes its sibling prefix index
// ("<hashFile>.index<prefixLen>"): one "PREFIX:OFFSET" line per distinct
// prefixLen-char hex prefix, where OFFSET is the byte offset of that prefix
// block's first line. The dump must be sorted (as the downloader writes it).
// Returns the number of index entries written. onProgress, if non-nil, is called
// periodically with the number of bytes scanned so a long build can report progress.
func BuildIndex(hashFile string, prefixLen int, onProgress func(scanned int64)) (int, error) {
	if prefixLen <= 0 {
		return 0, fmt.Errorf("invalid prefix length %d", prefixLen)
	}
	f, err := os.Open(hashFile)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 1<<20)
	var idx bytes.Buffer
	idx.Grow(1 << 24) // ~16 MiB; the full .index5 is ~19 MB

	var offset, sinceProgress int64
	last := make([]byte, 0, prefixLen)
	have := false
	atLineStart := true
	n := 0

	for {
		line, rerr := br.ReadSlice('\n') // no per-line allocation; lines are tiny
		if atLineStart && len(line) >= prefixLen {
			p := line[:prefixLen]
			if isHexPrefix(p) && (!have || !equalUpperHex(p, last)) {
				appendUpperHex(&idx, p)
				idx.WriteByte(':')
				idx.WriteString(strconv.FormatInt(offset, 10))
				idx.WriteByte('\n')
				last = appendUpperHexBytes(last[:0], p)
				have = true
				n++
			}
		}
		offset += int64(len(line))
		sinceProgress += int64(len(line))
		if onProgress != nil && sinceProgress >= 1<<30 { // ~every 1 GiB
			onProgress(offset)
			sinceProgress = 0
		}
		// rerr==nil means the read consumed through '\n' -> next read is a new line.
		atLineStart = rerr == nil
		if rerr != nil {
			if rerr == bufio.ErrBufferFull {
				continue // overlong line (won't happen for hash lines); keep counting bytes
			}
			if rerr == io.EOF {
				break
			}
			return 0, rerr
		}
	}
	if onProgress != nil {
		onProgress(offset)
	}
	if n == 0 {
		return 0, fmt.Errorf("no hash lines found in %s (is it a valid NTLM dump?)", hashFile)
	}
	if err := fsutil.WriteFileAtomic(IndexPath(hashFile, prefixLen), idx.Bytes(), 0o644); err != nil {
		return 0, err
	}
	return n, nil
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f')
}

func isHexPrefix(p []byte) bool {
	for _, b := range p {
		if !isHexByte(b) {
			return false
		}
	}
	return true
}

func upperHexByte(b byte) byte {
	if b >= 'a' && b <= 'f' {
		return b - 32
	}
	return b
}

func equalUpperHex(p, last []byte) bool {
	if len(p) != len(last) {
		return false
	}
	for i := range p {
		if upperHexByte(p[i]) != last[i] {
			return false
		}
	}
	return true
}

func appendUpperHex(buf *bytes.Buffer, p []byte) {
	for _, b := range p {
		buf.WriteByte(upperHexByte(b))
	}
}

func appendUpperHexBytes(dst, p []byte) []byte {
	for _, b := range p {
		dst = append(dst, upperHexByte(b))
	}
	return dst
}
