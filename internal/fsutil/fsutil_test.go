package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")

	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Fatalf("first write = %q, want one", b)
	}
	// overwrite in place
	if err := WriteFileAtomic(p, []byte("two-longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two-longer" {
		t.Fatalf("overwrite = %q, want two-longer", b)
	}
	// the temp file must be gone (renamed/cleaned) -- only the target remains
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "f.json" {
		names := make([]string, len(ents))
		for i, e := range ents {
			names[i] = e.Name()
		}
		t.Fatalf("expected only f.json, got %v", names)
	}
}
