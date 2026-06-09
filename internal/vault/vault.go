// Package vault provides encrypted-at-rest persistence for audit data. A random
// 32-byte data-encryption key (DEK) encrypts each audit with AES-256-GCM. The DEK
// itself is wrapped with a key-encryption key derived from an operator passphrase
// via argon2id and stored in a keyfile. The DEK exists in memory only after a
// successful Unlock, so on disk nothing is readable without the passphrase.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	keyfileName  = "keyfile.json"
	auditsSubdir = "audits"
	dekLen       = 32
	saltLen      = 16

	keyfileVersion = 1

	// argon2id parameters for deriving the key-encryption key. The unlock is rare,
	// so these are deliberately heavier than an interactive login KDF.
	argonTime    = 4
	argonMemory  = 128 * 1024 // 128 MiB
	argonThreads = 4
	// Floors accepted when reading an existing keyfile (older keyfiles + tamper guard).
	minArgonTime   = 2
	minArgonMemory = 32 * 1024
)

var (
	// ErrLocked is returned when an operation needs the DEK but the vault is locked.
	ErrLocked = errors.New("vault is locked")
	// ErrNotInitialized is returned when unlocking before a keyfile exists.
	ErrNotInitialized = errors.New("vault not initialized")
	// ErrBadPassphrase is returned when the passphrase fails to unwrap the DEK.
	ErrBadPassphrase = errors.New("incorrect passphrase")
	// ErrNoIndex is returned by LoadIndex when no index file exists yet.
	ErrNoIndex = errors.New("no index file")
)

type keyfile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Time       uint32 `json:"time"`
	Memory     uint32 `json:"memory"`
	Threads    uint8  `json:"threads"`
	WrappedDEK string `json:"wrapped_dek"`
}

// Vault stores encrypted audits under a directory. Safe for concurrent use.
type Vault struct {
	dir string
	mu  sync.RWMutex
	dek []byte // nil when locked
}

// Open prepares the data directory (creating it if needed). It does not unlock.
// If a keyfile is present it is parse-checked so a corrupt/truncated keyfile is
// surfaced at startup rather than silently treated as "initialized".
func Open(dir string) (*Vault, error) {
	if err := os.MkdirAll(filepath.Join(dir, auditsSubdir), 0o700); err != nil {
		return nil, err
	}
	v := &Vault{dir: dir}
	if v.Initialized() {
		if _, err := v.readKeyfile(); err != nil {
			return nil, fmt.Errorf("keyfile present but unreadable (a backup may exist at %s.bak): %w", v.keyfilePath(), err)
		}
	}
	return v, nil
}

// readKeyfile reads, parses, and validates the keyfile.
func (v *Vault) readKeyfile() (keyfile, error) {
	b, err := os.ReadFile(v.keyfilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return keyfile{}, ErrNotInitialized
		}
		return keyfile{}, err
	}
	var kf keyfile
	if err := json.Unmarshal(b, &kf); err != nil {
		return keyfile{}, fmt.Errorf("corrupt keyfile: %w", err)
	}
	if kf.Version != keyfileVersion || kf.KDF != "argon2id" {
		return keyfile{}, fmt.Errorf("unsupported keyfile (version %d, kdf %q)", kf.Version, kf.KDF)
	}
	if kf.Time < minArgonTime || kf.Memory < minArgonMemory || kf.Threads < 1 {
		return keyfile{}, errors.New("keyfile argon2 parameters below the accepted minimum")
	}
	return kf, nil
}

func (v *Vault) keyfilePath() string { return filepath.Join(v.dir, keyfileName) }
func (v *Vault) auditPath(id string) string {
	return filepath.Join(v.dir, auditsSubdir, id+".enc")
}

// Initialized reports whether a keyfile exists (i.e. a passphrase has been set).
func (v *Vault) Initialized() bool {
	_, err := os.Stat(v.keyfilePath())
	return err == nil
}

// Unlocked reports whether the DEK is currently held in memory.
func (v *Vault) Unlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.dek != nil
}

func deriveKEK(passphrase string, salt []byte, t, m uint32, p uint8) []byte {
	return argon2.IDKey([]byte(passphrase), salt, t, m, p, dekLen)
}

// wrapAndWrite wraps dek under a fresh-salt KEK from passphrase (current params)
// and writes the keyfile atomically, backing up any existing keyfile first.
func (v *Vault) wrapAndWrite(dek []byte, passphrase string) error {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	kek := deriveKEK(passphrase, salt, argonTime, argonMemory, argonThreads)
	wrapped, err := gcmSeal(kek, dek)
	if err != nil {
		return err
	}
	kf := keyfile{
		Version: keyfileVersion, KDF: "argon2id", Salt: b64(salt),
		Time: argonTime, Memory: argonMemory, Threads: argonThreads,
		WrappedDEK: b64(wrapped),
	}
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(v.keyfilePath()); err == nil {
		_ = os.WriteFile(v.keyfilePath()+".bak", old, 0o600) // best-effort backup before overwrite
	}
	return writeFileAtomic(v.keyfilePath(), b)
}

// Initialize sets the store passphrase on first run: generates a random DEK,
// wraps it under the passphrase, writes the keyfile, and unlocks.
func (v *Vault) Initialize(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := os.Stat(v.keyfilePath()); err == nil {
		return errors.New("vault already initialized")
	}
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	if err := v.wrapAndWrite(dek, passphrase); err != nil {
		return err
	}
	v.dek = dek
	return nil
}

// Unlock derives the key from the passphrase and unwraps the DEK into memory.
func (v *Vault) Unlock(passphrase string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	kf, err := v.readKeyfile()
	if err != nil {
		return err
	}
	salt, err := unb64(kf.Salt)
	if err != nil {
		return err
	}
	wrapped, err := unb64(kf.WrappedDEK)
	if err != nil {
		return err
	}
	kek := deriveKEK(passphrase, salt, kf.Time, kf.Memory, kf.Threads)
	dek, err := gcmOpen(kek, wrapped)
	if err != nil {
		return ErrBadPassphrase
	}
	v.dek = dek
	return nil
}

// ChangePassphrase re-wraps the existing DEK under a new passphrase (fresh salt +
// current argon2 cost). The encrypted audit blobs are untouched. The old keyfile
// is backed up to keyfile.json.bak. Requires the correct current passphrase.
func (v *Vault) ChangePassphrase(oldPass, newPass string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	kf, err := v.readKeyfile()
	if err != nil {
		return err
	}
	salt, err := unb64(kf.Salt)
	if err != nil {
		return err
	}
	wrapped, err := unb64(kf.WrappedDEK)
	if err != nil {
		return err
	}
	dek, err := gcmOpen(deriveKEK(oldPass, salt, kf.Time, kf.Memory, kf.Threads), wrapped)
	if err != nil {
		return ErrBadPassphrase
	}
	if err := v.wrapAndWrite(dek, newPass); err != nil {
		return err
	}
	v.dek = dek
	return nil
}

// Lock zeroes and drops the DEK.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.dek {
		v.dek[i] = 0
	}
	v.dek = nil
}

// SaveAudit encrypts plaintext under the DEK and writes it atomically.
func (v *Vault) SaveAudit(id string, plaintext []byte) error {
	v.mu.RLock()
	dek := v.dek
	v.mu.RUnlock()
	if dek == nil {
		return ErrLocked
	}
	ct, err := gcmSeal(dek, plaintext)
	if err != nil {
		return err
	}
	return writeFileAtomic(v.auditPath(id), ct)
}

func (v *Vault) indexPath() string { return filepath.Join(v.dir, "index.enc") }

// SaveIndex encrypts + writes the audit metadata index.
func (v *Vault) SaveIndex(plaintext []byte) error {
	v.mu.RLock()
	dek := v.dek
	v.mu.RUnlock()
	if dek == nil {
		return ErrLocked
	}
	ct, err := gcmSeal(dek, plaintext)
	if err != nil {
		return err
	}
	return writeFileAtomic(v.indexPath(), ct)
}

// LoadIndex decrypts the metadata index, or returns ErrNoIndex if absent.
func (v *Vault) LoadIndex() ([]byte, error) {
	v.mu.RLock()
	dek := v.dek
	v.mu.RUnlock()
	if dek == nil {
		return nil, ErrLocked
	}
	ct, err := os.ReadFile(v.indexPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoIndex
		}
		return nil, err
	}
	return gcmOpen(dek, ct)
}

// LoadOne decrypts a single audit blob.
func (v *Vault) LoadOne(id string) ([]byte, error) {
	v.mu.RLock()
	dek := v.dek
	v.mu.RUnlock()
	if dek == nil {
		return nil, ErrLocked
	}
	ct, err := os.ReadFile(v.auditPath(id))
	if err != nil {
		return nil, err
	}
	return gcmOpen(dek, ct)
}

// DeleteAudit removes an audit's encrypted file (no error if already gone).
func (v *Vault) DeleteAudit(id string) error {
	err := os.Remove(v.auditPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// LoadAll decrypts every stored audit, returning id -> plaintext.
func (v *Vault) LoadAll() (map[string][]byte, error) {
	v.mu.RLock()
	dek := v.dek
	v.mu.RUnlock()
	if dek == nil {
		return nil, ErrLocked
	}
	entries, err := os.ReadDir(filepath.Join(v.dir, auditsSubdir))
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") {
			continue
		}
		ct, err := os.ReadFile(filepath.Join(v.dir, auditsSubdir, e.Name()))
		if err != nil {
			return nil, err
		}
		pt, err := gcmOpen(dek, ct)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", e.Name(), err)
		}
		out[strings.TrimSuffix(e.Name(), ".enc")] = pt
	}
	return out, nil
}

// --- crypto + file helpers ---

func gcmSeal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil // nonce || ciphertext
}

func gcmOpen(key, blob []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// writeFileAtomic writes b durably: a temp file is written + fsync'd, then renamed
// over path, then the directory is fsync'd (best-effort). A crash leaves either the
// old file or the new file, never a truncated one.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".keyfile-*.tmp") // 0600 by default
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op once renamed
	if _, err := f.Write(b); err != nil {
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

func b64(b []byte) string            { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
