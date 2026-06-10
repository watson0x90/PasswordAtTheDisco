// Package fsutil provides durable filesystem helpers shared across the app.
package fsutil

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path durably: a temp file in the same directory is
// written + fsync'd + chmod'd to perm, then renamed over path, and the directory is
// fsync'd (best-effort). A crash leaves either the old file or the complete new one,
// never a truncated/partial one. Use it for any file that is rewritten in place and
// must survive a crash (config, keyfile, encrypted blobs, the metadata index).
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*") // same dir so the rename is atomic
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op once renamed
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // dir fsync; not supported everywhere
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
